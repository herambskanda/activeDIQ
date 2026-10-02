---
title: "Top 20 admin tasks: ManageEngine benchmark and activeDIQ targets"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
ticket: T-0008
sources_last_checked: 2026-10-02
---

# Top 20 admin tasks: ManageEngine benchmark and activeDIQ targets

**What this is.** This document lists the 20 jobs that AD admins and help-desk technicians do most in ManageEngine (ME) tools. For each job it records:
- how ME does it today: steps, screens and waits;
- what hurts, with sources;
- the budget activeDIQ must meet: interactions, screens and time.

T-0009 (information architecture) must give every task a path within its budget. Later design and QA tickets measure against the same numbers.

**What it is not.** These are not measured activeDIQ times; no activeDIQ code exists yet. The ME times are a model plus indicative waits from the public demo. They are not a stopwatch on a customer install. Nothing here may be quoted externally until §5 has been run (CV §6.2, ADM §4.2 `[TODO]`).

**Evidence base**
- **Our own read-only walk of ME's public demo:** ADManager Plus Professional, build 8041, on 2026-10-02. We clicked through but submitted nothing. Screenshots are in [`top-admin-tasks-benchmark-evidence/`](top-admin-tasks-benchmark-evidence/).
- **ME help docs and KB articles**, linked inline.
- **The research corpus:**
  - `ADM` = `knowledge/business/market-research/manageengine-admanager-plus.md`
  - `CV` = `…/manageengine-ad-customer-voice-and-security.md`
  - `ENH` = `knowledge/business/strategy/enhancement-catalog.md`

## Key takeaways

1. **The gap is in the jobs ME splits across screens, products or visits.**
   - Movers (T10): ≈31 interactions over ≈8 screens.
   - Stale-object cleanup (T17, T18): 36–39 interactions over two visits.
   - Lockout root cause (T02): two products.
   - Privileged-group forensics (T16): a separate product, ADAudit Plus.
   
   activeDIQ targets cut these by 60–70%.
2. **On single-object help-desk jobs, ME's click count is already low.** Examples: T01 reset + unlock (8–9 interactions) and T05 LAPS (≈5). On these jobs our edge is elsewhere:
   - **No page loads.** The demo's Reset Password Console took **14.5 s** to open, and the dashboard took **23.8 s**.
   - **Safe defaults.** ME's bulk reset form defaults to **"Same as logonname"**, and "must change at next logon" is unticked in the console.
   - **Status at a glance.** The search results grid shows names only, with no locked, disabled or expired status.
   
   We do not claim a click win where there isn't one.
3. **Bulk jobs fail on data handling, not clicks.** ME's CSV import needs LDAP attribute headers and DNs for `memberOf` and `OUName`. Per-row failure reasons, and retrying failed rows, are not documented. Our target is to accept an HR export as-is, validate every row before writing, and support "Retry 13 failed".
4. **Two enhancements add a step on purpose:**
   - caller verification on reset (ENH-09, +2 interactions);
   - a reason prompt on LAPS and BitLocker reveal (+1).
   
   Each is justified in its task. A tier-1 agent who resets a password for an unverified caller is the initial vector in documented attacks ([CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a); [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)).
5. **Totals across all 20 tasks:**

   | | ME | activeDIQ target |
   |---|---|---|
   | Interactions | 301 | 129 (−57%) |
   | Screens | 83 | 36 |
   | Modelled interaction time | ≈559 s | ≈277 s (−50%), before ME's page-load waits |

## 1. Method

### 1.1 How the 20 tasks were chosen

The tasks were chosen against four sources of evidence. A task made the list when at least two of them point to it:
1. the jobs in this role's brief: unlock + reset, bulk-create 200 from CSV, who removed someone from Domain Admins, stale computers;
2. frequency evidence (§1.4);
3. where ME itself puts shortcuts, which is a vendor signal:
   - the Home tile "Help Desk Reset Password Console";
   - the Home quick links "Account Provisioning (via Templates)" and "Account Deprovisioning" ([demo screenshot](top-admin-tasks-benchmark-evidence/me-01-home-dashboard.png));
   - Zia's chat actions ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/zia-configuration.html));
   - mobile-app actions ([help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-management/ad-management.html));
4. the personas in `product-strategy.md` §3.2.

The list covers the v1 ADManager Plus scope (D-0001) plus two jobs that ME sells in ADAudit Plus (T02 half, T16). We include those two because admins do these jobs from the same chair, and the "one console" claim is tested on them.

Jobs considered and left out are:
- delegating reset rights for an OU (a one-time setup);
- pre-staging a computer;
- GPO edits;
- NTFS permission changes (lower frequency, and not in the brief).

### 1.2 Counting rules (applied to both products)

**Start state:**
- logged in, on the home screen;
- knows the target's name;
- one domain and one M365 tenant (a multi-domain ME install adds 2 interactions to most domain pickers).

**End state:** the change is committed and confirmation is visible, or the answer is on screen.

**Screen:** a page load, or a modal, pop-up or side sheet that has to open. An activeDIQ side sheet counts as a screen even though it does not reload the page.

**Interaction:** one deliberate act. Each of these counts as 1:
- a click on a tab, link, button, checkbox or radio;
- selecting a list item;
- one keyboard shortcut or Enter;
- typing into one field, whatever its length;
- pasting a list.

Some acts count as more or less than 1:
- A drop-down = 2 (open, pick).
- An OS file picker = 1 screen + 2.
- Fields left at their default = 0.

**Typed fields (F)** are counted separately because they dominate time.

**ME step sources** are tagged on each step:
- `[demo]`: observed by us on 2026-10-02;
- `[doc]`: stated in the cited ME page;
- `[inferred]`: deduced from docs and screenshots.

ME counts are for the **shortest documented path** in the edition that has the feature. A prepared template is assumed where ME needs one, and the one-time setup is listed separately.

### 1.3 Time model

Time is modelled with the Keystroke-Level Model ([Card, Moran & Newell 1980](https://doi.org/10.1145/358886.358895); [summary](https://en.wikipedia.org/wiki/Keystroke-level_model)). The operator values are:
- P point = 1.1 s;
- B click = 0.2 s;
- H home hands = 0.4 s;
- K keystroke = 0.28 s;
- M mental preparation = 1.35 s.

They are simplified into one formula used for both products:

> **T = 1.3 s × non-typed interactions + 3.2 s × typed fields + 1.35 s × screens**

The components are:
- **1.3 s** = P + B per click. Keyboard shortcuts are also priced at 1.3 s, which is conservative and works against us.
- **3.2 s** = H + ≈10 characters × K per typed field.
- **1.35 s** = one M to orient on each new screen.

**System waits (W)** are kept separate:
- **ME's waits** are the demo timings we measured (§1.5). They are indicative only, because the demo is shared and remote.
- **activeDIQ's wait budget** is ≤ 1 s per screen, as p95 on the reference install. This is a **performance requirement**, and it is owned by the architecture (T-0004 follow-ups).
- **Long-running work** (bulk writes, reports over 12,000+ objects) gets its own runtime target. It runs in the background with progress, so it never blocks the admin's next task.

A **target** is the modelled activeDIQ time plus its wait budget, rounded up with at least 10% headroom for reading and checking. The point of a target is to fail a design that misses it.

### 1.4 Frequency evidence classes

| Class | Meaning |
|---|---|
| **A** | Measured statistic. Second-hand quotes are tagged `[UNVERIFIED original]` |
| **B** | A control or regulatory cadence forces the task (PCI DSS v4.0, CIS v8, NIST 800-53, Microsoft guidance) |
| **C** | Vendor signal: ME surfaces the task as a shortcut, mobile action or chat action |
| **D** | Community signal |
| **E** | No public evidence, so the frequency is an assumption, tagged `[UNVERIFIED]` |

The only per-population statistic found is **joiner/leaver volume**. In 2025 the US monthly hires and separations rates both averaged **3.3%** ([BLS JOLTS, Mar 2026 release](https://www.bls.gov/news.release/archives/jolts_03132026.htm)). That works out to ≈33 joiners and ≈33 leavers per 1,000 employees per month (our arithmetic). The figure covers all non-farm jobs, so office AD populations are probably lower (inference).

Primary frequency data from pilot customers is `[TODO]`. Ticket telemetry from warm accounts would replace classes C and E.

### 1.5 What we observed on the ME demo (2026-10-02, build 8041, Professional)

| Observation | Value | Evidence |
|---|---|---|
| Login → dashboard rendered | **23.8 s** | [me-01](top-admin-tasks-benchmark-evidence/me-01-home-dashboard.png) |
| Home tile → Help Desk Reset Password Console rendered | **14.5 s** | [me-02](top-admin-tasks-benchmark-evidence/me-02-helpdesk-reset-console.png) |
| Console grid columns | Employee ID, Full Name, SAM, Display Name, OU, Domain, Action. **No lock or status column by default**; "Lockout Time" is available through Add or Remove Column. 14 rows, **11 of them system or Exchange mailboxes** | me-02 |
| Reset pop-up | "Type a password" preselected. "User must change the password at next logon" **unticked**. "Account is locked out" is a checkbox, so unlock is part of the same pop-up. No caller-verification step | [me-03](top-admin-tasks-benchmark-evidence/me-03-helpdesk-reset-popup.png) |
| Header search "Search AD Objects" | Opens a **report** ("Search Users, Groups, Computers & Contacts") in ≈6 s. Result columns: SAM, Last, First, Common and Display Name. **No status** | [me-04](top-admin-tasks-benchmark-evidence/me-04-global-search-results.png) |
| Management › User Management landing | **87 links** on one page | [me-05](top-admin-tasks-benchmark-evidence/me-05-management-user-landing.png) |
| Management › Reset Password (bulk form) | Default **"Same as logonname"**. "Must change at next logon" is a drop-down set to **N/A** | [me-06](top-admin-tasks-benchmark-evidence/me-06-management-reset-password.png) |
| Create Single User | Full page reload, **16.1 s**. 3 required fields on the General tab, 9 tabs | [me-07](top-admin-tasks-benchmark-evidence/me-07-create-single-user.png) |
| Create Bulk Users | Full page reload, **22.6 s**. On-page guidance: "Specify memberOf, manager in DN format … and ouName in DN format enclosed by double quotes" | [me-08](top-admin-tasks-benchmark-evidence/me-08-create-bulk-users.png) |
| Inactive Computers report | Default period **"Last 30 days"**. Results served from a cached run ("Generated on 2026-09-24"). Last Logon Time shows a raw `0`. Toolbar: Delete, Disable, Move, "…", Create Request | [me-09](top-admin-tasks-benchmark-evidence/me-09-inactive-computers-report.png) |
| BitLocker Recovery Keys | A domain-wide **report** that must be generated. There is no single-computer or key-ID lookup field | [me-10](top-admin-tasks-benchmark-evidence/me-10-bitlocker-recovery-keys.png) |

All values are single-session, shared-demo and remote-network measurements, so treat them as **directional**. They match the earlier pass in ADM §4.2 (dashboard ≈24 s, Create Single User ≈20 s).

### 1.6 Personas (from `product-strategy.md` §3.2)

| Code | Persona |
|---|---|
| **HD** | Help-desk technician, tier 1. Phone in one hand; often no AD rights of their own |
| **AD** | AD / systems admin |
| **SEC** | Security / SOC |
| **CMP** | Compliance / audit |

## 2. Summary

How to read the table:
- **I/F/S** = interactions / typed fields / screens.
- **ME T** = modelled interaction time **before** waits.
- **ME W** = demo-observed waits on the path, where we measured them.
- **Target** = the activeDIQ budget that design and QA must meet.

| ID | Task | Persona | Frequency (class) | ME path (product · edition) | ME I/F/S | ME T | ME W | aDIQ I/F/S | Target |
|---|---|---|---|---|---|---|---|---|---|
| T01 | Reset password + unlock for a caller | HD | Daily, many per day (A, C) | ADMP Reset Password Console · Std+Pro | 9/3/2 | 20 s | 14.5 s + search | 7/2/2 (5/1/2 without verification) | **≤ 20 s** (≤ 15 s) |
| T02 | Find a repeated lockout's source, then unlock | HD | Weekly–daily (B, C; E) | ADAP Lockout Analyzer (**Pro**) + ADMP unlock · **2 products** | 13/2/5 | 28 s | n/m | 5/1/1 | **≤ 15 s** |
| T03 | Look up a caller's account status | HD | Daily, before most T01/T02 (C) | ADMP search + AD Explorer · Std+Pro (Entitlements: Pro+GRC) | 9/1/2 | 16 s | ≈6 s search | 3/1/1 | **≤ 10 s** |
| T04 | Retrieve a BitLocker recovery key | HD | Occasional, with incident spikes (C) | ADMP BitLocker report · Std+Pro | 8/1/2 | 15 s | report run | 5/1/2 | **≤ 15 s** |
| T05 | Retrieve a LAPS password | HD, AD | Weekly (C; E) | ADMP AD Explorer tree · n/s | 5/0/2 | 9 s | n/m | 5/1/2 | **≤ 15 s** (parity, plus audit) |
| T06 | Add or remove a user in a group | HD, AD | Daily–weekly (B, C) | ADMP Group Attributes · Std+Pro (group side: Pro) | 12/2/3 | 23 s | n/m | 7/2/2 | **≤ 20 s** |
| T07 | Create one joiner (mailbox, licence, groups) | AD | ≈33 / 1,000 staff / month (A) | ADMP Create Single User + template · Std+Pro | 8/2/3 (System Template: 32/8/5) | 18 s | 16.1 s | 6/3/1 | **≤ 25 s** |
| T08 | Bulk-create 200 users from CSV | AD | Seasonal / event-driven (E) | ADMP Create Bulk Users · Std+Pro | 10/0/6 + CSV rework | 21 s | 22.6 s | 5/0/2 | **≤ 15 s** of interaction; 200 rows validated ≤ 10 s, created ≤ 120 s |
| T09 | Offboard a leaver | AD | ≈33 / 1,000 staff / month (A, B) | ADMP Disable + policy + M365 mailbox task · Std+Pro | 17/2/5 (+13 setup) | 33 s | M365 tab ≈26 s | 5/1/2 | **≤ 20 s** |
| T10 | Process a mover (title, manager, groups, OU) | AD, HD | Unknown (E; B) | ADMP Modify Single User + Move Users · Std+Pro | 31/6/8 | 63 s | n/m | 12/5/2 | **≤ 40 s** |
| T11 | Add 50 users to one group | AD | Unknown (E; C) | ADMP Group Attributes + CSV · Pro `[UNVERIFIED Std]` | 14/1/5 + CSV | 27 s | n/m | 8/1/2 | **≤ 20 s** |
| T12 | Change one attribute on 300 users | AD | Unknown (E; C) | ADMP Organization Attributes · Std+Pro | 10/1/4 | 20 s | n/m | 8/3/2 | **≤ 25 s** |
| T13 | Set or extend a contractor's expiry | HD, AD | Unknown (B, C) | ADMP Modify Single User › Account · Std+Pro | 15/1/4 | 27 s | n/m | 6/2/1 | **≤ 18 s** |
| T14 | Assign or change an M365 licence | AD | Tracks T07/T09 (C; E) | ADMP M365 tab › Assign/Remove Licenses · Std+Pro | 13/1/3 | 23 s | ≈26 s tab | 6/1/2 | **≤ 18 s** |
| T15 | Restore a user deleted by mistake | AD | Rare (E) | ADMP Restore Deleted Users · Std+Pro (needs Recycle Bin) | 9/1/3 | 18 s | n/m | 5/1/2 | **≤ 15 s** |
| T16 | Who removed X from Domain Admins, and when | SEC, AD | Logs reviewed daily; investigations on events (B, C) | **ADAudit Plus** group report · separate product | 11/1/2 (+ DC audit setup) | 19 s | n/m | 5/2/1 | **≤ 15 s** |
| T17 | Clean up stale computers (90 d → disable → quarantine → delete) | AD | Monthly–quarterly (B) | ADMP Inactive Computers report, 2 visits · Std+Pro | 36/0/8 | 58 s | report run | 8/1/3 | **≤ 30 s** |
| T18 | Clean up inactive users, excluding service accounts | AD, CMP | Every 45–90 days (B) | ADMP Inactive Users report, 2 visits · Std+Pro | 39/1/9 | 65 s | report run | 10/1/3 | **≤ 45 s** |
| T19 | Export Domain Admins membership, nested, for an auditor | CMP, SEC | Every 6 months (PCI) to quarterly (B) | ADMP Detailed Group Members report · Std+Pro | 13/1/3 | 23 s | report run | 6/1/1 | **≤ 15 s** |
| T20 | Schedule a monthly compliance report by e-mail | CMP | Set up rarely, runs monthly (B, C) | ADMP Schedule Reports · **Pro** | 19/2/4 | 34 s | n/m | 7/2/2 | **≤ 25 s** |
| | **Total** | | | | **301 / 83 screens** | **≈559 s** | | **129 / 36 screens** | **≈277 s modelled** |

*n/m = not measured on the demo.*

Three tasks are not a click win, and the summary should not suggest otherwise:
- **T05:** we are at parity on clicks (5 vs 5). The reveal reason adds a typed field, so the modelled time is 11 s vs 9 s. We still target ≤ 15 s.
- **T07:** we are at parity with a well-prepared ME template.
- **T12:** we are at near parity.

On those three tasks we win on waits, defaults, previews and undo, not clicks.

## 3. Task detail

Every task follows the same structure:
- frequency evidence;
- the ME flow with sourced steps;
- pain points;
- the activeDIQ target flow;
- the target and its justification;
- the states the design must cover.

The activeDIQ flows rely on the shared patterns in §4 (P1–P8).

### T01 · Reset password + unlock for a caller (HD)

**Frequency (A, C).**
- Password resets are "20% to 50% of all help desk calls", attributed to Gartner ([TechTarget, 2011](https://www.techtarget.com/enterprise-software/tip/Resetting-passwords-in-the-enterprise-without-the-help-desk); [The Hacker News, 2021](https://thehackernews.com/2021/04/cost-of-account-unlocks-and-password.html)). `[UNVERIFIED original]`
- ME's own page says "one third" of help-desk calls are password resets; the claim is unsourced vendor copy ([ME](https://www.manageengine.com/products/ad-manager/delegate-ad-password-reset-and-account-unlock-permissions.html)).
- ME gives the task a dedicated Home tile ([me-01](top-admin-tasks-benchmark-evidence/me-01-home-dashboard.png)) and a Zia chat action ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/zia-configuration.html)).

**ME flow: Help Desk Reset Password Console** ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/active-directory-reset-password.html)). Totals: **9 I / 3 F / 2 S**; the page load observed was 14.5 s.
1. Click the "Help Desk Reset Password Console" tile on Home `[demo]`. A page load follows (14.5 s).
2. Type the name in the grid search `[demo]`.
3. Press Enter `[demo]`.
4. Click "Reset Password" on the user's row. A pop-up opens `[demo]`.
5. Type the password `[demo]`. "Type a password" is preselected; choosing "Generate password" instead saves one typed field.
6. Type the confirmation `[demo]`.
7. Tick "User must change the password at next logon" `[demo]`.
8. Tick "Account is locked out" `[demo]`.
9. Click OK `[demo]`.

**Alternative ME path: Management › Reset Password, then Unlock Users.** It takes 17 I and 4–5 S, and its default is **"Same as logonname"** ([me-06](top-admin-tasks-benchmark-evidence/me-06-management-reset-password.png); [help](https://www.manageengine.com/products/ad-manager/help/user_management/general_attributes/reset_password_windows_users.html)).

**Pain points**
- The console does not show whether the account is locked before you open the pop-up, because the lock column is off by default ([me-02](top-admin-tasks-benchmark-evidence/me-02-helpdesk-reset-console.png)).
- The grid mixes system and Exchange mailboxes in with people: 11 of 14 rows on the demo (me-02).
- Must-change is off by default (me-03), so the technician knows a live password.
- There is no caller-verification step anywhere in ADMP. Help-desk-assisted verification needs ADSSP (ENH-09, ADSS W9).
- The console's help page does not mention unlock at all (help above).

**activeDIQ flow.** Totals: **7 I / 2 F / 2 S**, or 5 I / 1 F / 2 S when policy waives verification.
1. Press `/`.
2. Type "priya r". The results already carry status chips: `Locked 09:12`, `Password expired`.
3. Press Enter. The user page opens with a banner: "Locked out 3× today. Last from LT-LON-0421" (P2).
4. Press `R`, "Reset & unlock". The sheet opens with these defaults:
   - a generated passphrase that meets policy;
   - "must change at next logon" **on**;
   - "unlock" **on** because the account is locked.
5. Click "Send code to •••• 4821" (ENH-09).
6. Type the code the caller reads back.
7. Press Enter to confirm.

The result shows the password with copy and a phonetic read-out. The audit line reads: "who, what, when, verified by OTP". Undo does not apply to a password reset.

**Target: ≤ 20 s with verification (model 17.6 s), ≤ 15 s without (model 13.1 s). No page load.**
- **Justification.** Verification adds 2 interactions over the shortest unsafe path. That is deliberate. Service-desk social engineering is a documented initial vector ([CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a); LAND §4.2).
- Even with verification, we stay below ME's 9 interactions, and we remove the 14.5 s console load.
- **States to design:**
  - not locked, so the unlock toggle is hidden rather than shown unchecked;
  - caller has no enrolled factor, so the sheet falls back to a manager-approval path;
  - code wrong 3×, so the attempt is blocked and logged;
  - target is a privileged account, which needs a typed confirmation plus a second approver per policy (P6);
  - the technician lacks rights on the user's OU, so the sheet explains why and who can help (P8);
  - a DC is unreachable, so the reset goes to a named DC and the sheet shows "replicating…" (P7).

### T02 · Find a repeated lockout's source, then unlock (HD)

**Frequency (B, C; E for volume).**
- PCI DSS 8.3.4 locks an account after no more than 10 failed attempts ([MS Learn PCI 8](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-8)).
- ME sells a dedicated Account Lockout Analyzer in its Professional edition ([ADAP](https://www.manageengine.com/products/active-directory-audit/windows-ad-user-account-lockout-analyzer.html)).
- Volume per week: `[UNVERIFIED]`.

**ME flow.** Totals: **13 I / 2 F / 5 S across two products and two licences.**

*Half 1: ADAudit Plus Account Lockout Analyzer* (Professional) ([how-to](https://www.manageengine.com/products/active-directory-audit/how-to/find-out-what-is-locking-ad-account.html)). This half is 3 S and 7 I:
1. Open the Active Directory tab `[doc]`.
2. Open User Management `[inferred]`.
3. Open Account Lockout Analyzer `[doc]`.
4. Open the grid search `[inferred]`.
5. Type the name `[inferred]`.
6. Press Enter `[inferred]`.
7. Click "Details" `[doc]`. A modal opens with checks of services, scheduled tasks, drive maps, sessions and processes.

*Half 2: unlock in ADManager Plus* ([help](https://www.manageengine.com/products/ad-manager/help/user_management/general_attributes/reset_password_windows_users.html)), because ADAudit Plus documents no unlock action. This half is 2 S and 6 I:
1. Management tab.
2. Unlock Users.
3. Type the name.
4. Search.
5. Tick the user.
6. Apply.

**Pain points**
- Two consoles: "For reports, we have to go back to ADAudit, which is not ideal." ([PeerSpot, Jai S, 2023-07-18](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))
- The analyzer is Professional-only ([pricing](https://www.manageengine.com/products/active-directory-audit/pricing-details.html)).
- OWA and ActiveSync sources need IIS logging ([help](https://www.manageengine.com/products/active-directory-audit/help/usecase/account-lockout-analyzer-overview.html)).

**activeDIQ flow.** Totals: **5 I / 1 F / 1 S.**
1. Press `/`.
2. Type the name.
3. Press Enter. The user page opens with the lockout panel already expanded. It lists the last lockouts, each with:
   - the **caller computer**, from DC event 4740 ([MS Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740));
   - the DC;
   - the time;
   - the failure count.
4. Click "Show failed sign-ins" to see the per-source breakdown.
5. Click "Unlock", or press `U`.

The next best action is offered as a link rather than another flow: "Notify user / open task on LT-LON-0421".

**Target: ≤ 15 s to see the source host and unlock (model 10.8 s).**
- **Justification.** Diagnosis and the fix live on one page, in one product. This is the lockout root-cause half of the help-desk lead's win (`product-strategy.md` §3.2).
- **Dependency.** The source host needs DC security-event collection (DC agent or event forwarding, Phase 2). Process-level cause on the endpoint needs endpoint data (ENH catalog, lockout root cause).
- **Before that data arrives**, the panel shows "Lockout source needs DC event collection: set up". This is the empty state. We never show a blank panel.
- **States to design:**
  - no events collected yet;
  - events older than retention;
  - source is a non-domain device (shows IP only);
  - locked again within minutes of unlock, which prompts "fix the source first".

### T03 · Look up a caller's account status (HD)

**Frequency (C).**
- This lookup precedes most T01 and T02 calls (inference).
- The ME mobile app ships reports for locked-out, disabled and password-expired users ([help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-reporting/ad-reporting.html)).
- The ME dashboard leads with the same counts (me-01).

**ME flow.** Totals: **9 I / 1 F / 2 S.**
1. Type in "Search AD Objects".
2. Press Enter. This opens a search **report**, ≈6 s `[demo]`. The result columns are names only: SAM, Last, First, CN and Display ([me-04](top-admin-tasks-benchmark-evidence/me-04-global-search-results.png)).
3. Getting status needs either extra columns, which only the built-in admin can set globally ([help](https://www.manageengine.com/products/ad-manager/help/user_management/searching_active_directory_users_groups_computers.html)), or AD Explorer:
   - open AD Explorer;
   - browse the tree 2–3 levels to the OU;
   - click the user;
   - open the Entitlements tab for groups ([help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html)). Entitlements needs Professional plus the GRC add-on ([FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html)).

All counts here are `[inferred]`, at low confidence.

**activeDIQ flow.** Totals: **3 I / 1 F / 1 S.**
1. Press `/`.
2. Type the name, sAMAccountName, UPN, e-mail or employee ID. Each result row shows status chips:
   - enabled or disabled;
   - locked;
   - password expired or expiring in N days;
   - account expires;
   - last sign-in.
   
   **For "is it locked / disabled / expired?", the answer is here, at 2 interactions.**
3. Press Enter for the full page: groups (direct and effective), devices, licences and recent changes.

**Target: ≤ 10 s (model 8.2 s).**
- **Justification.** One search that understands every identifier admins quote, with status in the result row.
- **States to design:**
  - **stale data.** `lastLogonTimestamp` replicates with up to ~14 days of lag ([MS Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp)). The chip says "Last sign-in ≈ 3 Oct (±14 d)", and the precise value is fetched from all DCs on demand;
  - ambiguous matches: two "Priya Raman"s show their department and OU to tell them apart;
  - out-of-scope objects are shown greyed with the reason (P8);
  - deleted objects carry a "Deleted" chip (T15).

### T04 · Retrieve a BitLocker recovery key (HD)

**Frequency (C).**
- Usually occasional, with extreme spikes. The 19 July 2024 CrowdStrike incident hit about 8.5 million Windows devices ([TechTarget](https://www.techtarget.com/cybersecurity/news/366596532/Microsoft-Faulty-CrowdStrike-update-affected-85M-devices)).
- Recovering those devices could require recovery keys ([CrowdStrike AD guide](https://crowdstrike.com/wp-content/uploads/2024/07/BitLocker-recovery-in-Microsoft-environments-using-Active-Directory-and-GPOs.pdf)).

**ME flow** ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-computer-reports.html); [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/unlock-and-recover-bitlocker-encrypted-drives.html)). Totals: **8 I / 1 F / 2 S.**
1. Open the Reports tab.
2. Open Computer Reports.
3. Open BitLocker Recovery Keys.
4. Tick the domain.
5. Click Generate. This runs a domain-wide report ([me-10](top-admin-tasks-benchmark-evidence/me-10-bitlocker-recovery-keys.png)).
6. Open the grid search.
7. Type the computer name.
8. Press Enter.

**Pain points**
- The flow is a domain-wide report, not a lookup.
- There is no lookup by the **recovery key ID**, which is the identifier the user can actually read off the pre-boot screen ([MS Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-process)).
- No reveal step or audit of who viewed a key is documented.
- Build 8030 added a "dedicated interface" with no help page ([RN](https://www.manageengine.com/products/ad-manager/release-notes.html)). Its flow is `[UNVERIFIED]`.

**activeDIQ flow.** Totals: **5 I / 1 F / 2 S.**
1. Press `/`.
2. Type the **computer name or the first 8 characters of the key ID**.
3. Press Enter.
4. Click "Show recovery key".
5. Pick a reason (a preset such as "Caller on phone", or a ticket number).

The key appears in 6-digit groups with copy. The view is audited.

**Target: ≤ 15 s (model 13.1 s).**
- **Justification.** A key-ID lookup removes the "what is your computer called?" exchange. The reason step adds 1 interaction on purpose, because a recovery key unlocks a whole disk.
- **States to design:**
  - several keys for one computer (one per volume, and older protectors), with the newest first and dated;
  - no key escrowed, which says so plainly and links to the escrow policy;
  - the key stored in Entra only (hybrid devices) is shown from Graph with its source labelled;
  - **incident mode**: a bulk lookup that pastes 200 key IDs and exports a list. This is the CrowdStrike case, and it pairs with P4.

### T05 · Retrieve a LAPS password (HD, AD)

**Frequency (C; E for volume).**
- ADMP ships a "LAPS Role" for technicians ([RN 8020](https://www.manageengine.com/products/ad-manager/release-notes.html)).
- ADAudit Plus audits LAPS reads ([help](https://www.manageengine.com/products/active-directory-audit/help/usecase/laps-auditing-reporting-capabilities.html)).
- Weekly volume is `[UNVERIFIED]`.

**ME flow, Windows LAPS** ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/export-laps-password-reports.html)). Totals: **5 I / 0 F / 2 S.**
1. Open AD Explorer.
2. Expand the tree 2–3 levels. The count depends on OU depth.
3. Click the computer.
4. Read "LAPS Details" on the Properties tab.

All counts here are `[inferred]`. Legacy LAPS goes through a report plus "Add or Remove Column", about 12 I.

**Pain points**
- There are two different paths for legacy and Windows LAPS.
- Viewing is audited only in ADAudit Plus, a separate product.
- ME's KB still names a setting that its release notes say was removed ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/fix-laps-password-not-visible.html)).

**activeDIQ flow.** Totals: **5 I / 1 F / 2 S.**
1. Press `/`.
2. Type the computer name.
3. Press Enter.
4. Click "Show local admin password".
5. Pick a reason.

Copy is offered, with an optional "rotate after use" toggle. Windows LAPS supports post-authentication rotation ([MS Learn](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)).

**Target: ≤ 15 s (model 13.1 s). Parity on interactions; the reason step adds +1 typed field over ME on purpose.**
- **Justification.** A LAPS password is local-admin access. The view must be audited in the same product that showed it (TM Tier-0 posture).
- Search beats tree-browsing as OU depth grows: ME's count rises by one click per OU level.
- **States to design:**
  - legacy and Windows LAPS on the same estate, shown with one label;
  - password expired or rotation pending;
  - an encrypted Windows LAPS password the technician cannot decrypt, which explains who can (P8).

### T06 · Add or remove a user in a group (HD, AD)

**Frequency (B, C).**
- PCI DSS 7.2.3 requires approved privilege changes ([MS Learn PCI 7](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-7)).
- Group membership is an action in the ME mobile app ([help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-management/ad-management.html)).

**ME flow: Bulk User Modification › Group Attributes, Std+Pro** ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html)). Totals: **12 I / 2 F / 3 S**; add and remove can be done in one pass.
1. Management tab.
2. Group Attributes.
3. Click "+" by Add to Group.
4. Pick the group.
5. OK.
6. Click "+" by Remove from Group.
7. Pick the group.
8. OK.
9. Type the user.
10. Search.
11. Tick the user.
12. Apply.

Other paths:
- The Modify Single User path is 14 I / 4 S, with an Action drop-down and a template pop-up before any edit ([help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-single-user.html)).
- Group-side management is Professional-only ([pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html)).

**activeDIQ flow.** Totals: **7 I / 2 F / 2 S.**
1. Press `/`.
2. Type the user.
3. Press Enter.
4. Press `G`, "Add to group".
5. Type the group name in the type-ahead.
6. Press Enter. A preview reads: "+1 group: SG-Finance-Readers (members 3,114)" (P3).
7. Confirm.

A toast with Undo appears (P5). To remove: on the Groups tab, select the row, press Delete, then Confirm (+3). The same sheet works from the group side, and for many users (T11).

**Target: ≤ 20 s (model 17.6 s).**
- **Justification.** The action lives where the object is. No template pop-up stands between the technician and the edit.
- **States to design:**
  - **protected or privileged group** (Domain Admins, Enterprise Admins, Schema Admins, AdminSDHolder-protected and custom Tier-0 groups). This needs typed confirmation plus an approver per policy, and the impact line reads "grants Tier-0" (P6);
  - nested-group effect: "also grants 4 groups via nesting";
  - already a member;
  - cross-domain group;
  - out-of-scope group (P8).

### T07 · Create one joiner with mailbox, licence and groups (AD)

**Frequency (A).**
- About 33 hires per 1,000 employees per month ([BLS JOLTS](https://www.bls.gov/news.release/archives/jolts_03132026.htm)).
- ME puts "Account Provisioning (via Templates)" in the Home quick links (me-01).

**ME flow: Create Single User with a prepared template** ([help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html); [templates](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html)). Totals: **8 I / 2 F / 3 S; 16.1 s page load** ([me-07](top-admin-tasks-benchmark-evidence/me-07-create-single-user.png)).
1. Management tab.
2. Create Single User. This is a full reload, 16.1 s `[demo]`.
3. Template drop-down (2).
4. First name and last name. Naming formats derive the rest `[inferred]`.
5. Create.

With the **System Template** (no preparation), the count rises to **32 I / 8 F / 5 S**:
- 3 mandatory fields: Logon Name, pre-Windows 2000 name and Full name (me-07);
- an OU picker;
- a group picker;
- Country, which is mandatory before an M365 licence can be applied (help above).

One-time setup for either path:
- the template;
- naming formats;
- tenant onboarding.

**Pain points**
- The page weighs 10.4 MB (ADM §4.2).
- Changing the domain mid-form "will reset all domain specific attributes" (help).
- Mailbox follow-ups are deferred to a "Delayed Management Tasks" queue (help).
- Naming formats are macro strings such as `%givenName%1[L]()%sn%2[L]()` (ADM §4.1).

**activeDIQ flow.** Totals: **6 I / 3 F / 1 S.**
1. Press `N`, "New user". The last-used role template is preselected, for example "Sales · London".
2. Type the first name.
3. Type the last name.
4. Type the manager in the type-ahead.
5. Press Enter.
6. Click Create.

As the admin types, a live preview panel shows every derived value:
- UPN, sAMAccountName, display name and e-mail, **each checked for duplicates**;
- the OU;
- the 3 groups;
- the licence, and a usageLocation derived from the office.

Each derived value is editable in place. The result page shows AD, mailbox and licence each with their own status. Mailbox provisioning shows "pending (Exchange Online), usually < 5 min" instead of a silent queue.

**Target: ≤ 25 s (model 15.9 s, plus manager search time). Interaction parity with a prepared ME template; the win is in what the admin can see.**
- **Justification:**
  - no 16 s page load;
  - duplicates and the derived names are visible **before** create;
  - one form covers AD, Exchange and M365;
  - templates import from ME (ENH-02), so the "prepared template" assumption holds on day one.
- **States to design:**
  - a name collision is shown inline, with the next free value suggested;
  - a manager not found;
  - the licence pool is empty: "0 of 250 E3 seats free", and create continues without the licence, with a follow-up task;
  - partial success: AD created but the mailbox failed. The result says exactly which parts succeeded and offers retry;
  - unicode names: "Zoë Ångström-Łukasiewicz" gets a transliterated sAMAccountName and the full display name;
  - a 40-character display name that truncates in the preview.

### T08 · Bulk-create 200 users from CSV (AD)

**Frequency (E).**
- No public frequency data was found. The job is event-driven: an intake season, an acquisition or a contractor batch `[UNVERIFIED]`.
- The role brief names it as a benchmark job.

**ME flow: Create Bulk Users** ([help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_multiple_windows_users.html); [CSV format](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-user-creation-csv.html)). Totals: **10 I / 0 F / 6 S; 22.6 s page load, plus CSV rework.**
1. Management tab.
2. Create Bulk Users. This is a full reload, 22.6 s `[demo]` ([me-08](top-admin-tasks-benchmark-evidence/me-08-create-bulk-users.png)).
3. Template drop-down (2).
4. Click Import. A modal opens.
5. OS file picker (2).
6. Import.
7. Review the grid. Rows are editable.
8. Next.
9. Pick the OU.
10. Create Users. The status step follows.

**CSV rules the admin must meet** (CSV format page):
- headers must be "attribute names as defined in the Active Directory";
- `memberOf` and `OUName` must be DNs, with `OUName` quoted (the on-page hint says the same, me-08);
- country needs all three of `c`, `co` and `countryCode`;
- the help's own sample uses `managedby` for the manager, which conflicts with the format page.

**Pain points**
- An HR export cannot be imported as-is.
- ME's KB warns that CSV runs can end in "error messages, partial updates, or no changes being applied" ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/csv-bulk-modification-failure-reasons.html)).
- Per-row failure reasons and retrying only the failed rows are **not documented** `[UNVERIFIED]`.
- "Validate CSV" exists only for modify-via-template ([help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-users-using-template.html)).

**activeDIQ flow.** Totals: **5 I / 0 F / 2 S** before fixes. The flow is one page in three states: Map, Validate, Run.
1. Press `N`, then choose "Import users".
2. Drop the file (or 2 with the OS picker).
3. **Map.** Columns map automatically from friendly headers ("First name", "Surname", "Manager email", "Dept"). Unmapped columns are flagged. Confirm the mapping (1).
4. **Validate.** A dry run checks every row before any write:
   - duplicates within the file and against the directory;
   - the manager and groups resolve;
   - the OU exists, or comes from the role rule;
   - password policy;
   - licence seats.
   
   Result: "**196 ready · 4 need attention**". Each problem row is fixable inline or can be excluded.
5. **Run.** Click "Create 196". Progress runs in the background. The admin can leave the page, and a notification fires when it is done.

The result reads: "**187 of 200 created. 13 failed. Here is why**", with the failures grouped by reason (for example "8 × manager not found", "5 × UPN suffix not allowed"). From the result the admin can use **Retry failed after fixing**, **Export failures**, and **Undo this batch** for objects created by it (P5).

**Target: ≤ 15 s of interaction (model 11.2 s) before row fixes. Validating 200 rows ≤ 10 s. Creating 200 users ≤ 120 s on the reference lab (T-0012), running in the background.**
- **Justification:**
  - the admin's time goes into data, not syntax;
  - we accept the file HR already produces;
  - the partial-failure state is designed, not an afterthought.
- **The runtime target is a starting budget** for the directory-engineer to confirm, not a measured number.
- **States to design:**
  - an empty or unreadable file;
  - wrong encoding: the preview shows "Ã¶" and offers re-decoding;
  - **12,000 rows**: virtualised grid, validation streams;
  - all rows fail;
  - a duplicate row inside the file;
  - permission denied on the target OU for some rows only.

### T09 · Offboard a leaver (AD)

**Frequency (A, B).**
- About 33 separations per 1,000 employees per month ([BLS JOLTS](https://www.bls.gov/news.release/archives/jolts_03132026.htm)).
- PCI DSS 8.2.5: access for terminated users is "immediately revoked" ([MS Learn PCI 8](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-8)).
- ME puts "Account Deprovisioning" in the Home quick links (me-01).

**ME flow per leaver.** Totals: **17 I / 2 F / 5 S, after a 13-interaction one-time policy setup.** The policy is set under Admin › Delete/Disable Policy ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/windows-active-directory-delete-policy.html)).
1. Management tab.
2. Enable/Disable Users.
3. Choose Disable.
4. Type the name.
5. Search.
6. Tick the user.
7. Apply. The policy then removes groups, moves the OU and revokes the licence.

Shared-mailbox conversion is a **separate** M365-tab task, about 10 more interactions in the iframe app, which renders in ≈26 s (ADM §4.2; [help](https://www.manageengine.com/products/ad-manager/help/office365/mailbox-management/mailbox-management.html)).

**Pain points**
- **No preview** of what the policy will change (ADM §4.3).
- On-premises, the policy *disables* the mailbox rather than converting it (policy help).
- Automating this needs Professional orchestration ([help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html)).

**activeDIQ flow.** Totals: **5 I / 1 F / 2 S.**
1. Press `/`.
2. Type the name.
3. Press Enter.
4. Press `O`, "Offboard". The **leaver plan** opens from policy, with every line listed and toggleable:
   - disable;
   - reset to a random password;
   - remove 14 groups, each named;
   - move to `OU=Leavers`;
   - revoke 2 licences;
   - convert the mailbox to shared and grant the manager access;
   - hide from the GAL;
   - revoke sessions.
   
   A "When" control offers "now" or "end of day 31 Oct".
5. Confirm.

**Target: ≤ 20 s (model 13.1 s).**
- **Justification.** One plan across AD, Exchange and M365, previewed before it runs (ENH-04). Disable, groups, OU and licence are undoable for a set period (P5).
- **States to design:**
  - the leaver is in privileged groups: typed confirmation, and the plan flags "removes Tier-0 access" (P6);
  - the leaver manages 6 direct reports: prompt to reassign;
  - the mailbox is on litigation hold;
  - scheduled offboarding is visible on the user page as a countdown;
  - partial failure: AD done but licence revoke failed, with retry.

### T10 · Process a mover: title, department, manager, groups, OU (AD, HD)

**Frequency (E; B).**
- No public internal-mobility rate was found `[UNVERIFIED]`.
- PCI DSS 8.2.4 requires approved changes to user IDs ([MS Learn PCI 8](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-8)).

**ME flow: Modify Single User, plus a separate Move Users task** ([help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-single-user.html); [bulk mod help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html)). Totals: **≈31 I / 6 F / 8 S.**
1. Management tab.
2. Modify Single User.
3. Search for the user.
4. Action, then Modify User.
5. Template OK.
6. Change the organisation fields, with a manager picker.
7. Remove the old group, then add the new one through the picker.
8. Preview.
9. Update.
10. Then **Move Users**, a separate page with an OU picker:
    - search;
    - tick the user;
    - Apply.

Copying groups from a colleague via "Copy User Attributes" is `[UNVERIFIED]` for `memberOf`; whether it appends or replaces is not documented ([help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-copy-user.html)).

**Pain points**
- Two tasks for one job.
- Copy-access behaviour is undocumented.

**activeDIQ flow.** Totals: **12 I / 5 F / 2 S.**
1. Press `/`.
2. Type the name.
3. Press Enter.
4. Press `M`, "Change role".
5. Type the title.
6. Type the department.
7. Type the manager.
8. Press Enter.
9. Type a colleague under "Match access to".
10. Press Enter.
11. Review the **diff**:
    - "+3 groups / −2 groups", each one named and individually untickable;
    - "OU: Sales → Finance (rule: department)".
12. Confirm.

The diff states clearly that matching access **replaces**, it does not append, and it lists what is removed.

**Target: ≤ 40 s (model 29.8 s).**
- **Justification:**
  - one sheet, one preview, one audit entry for the whole move;
  - "same access as" is the request help desks actually receive;
  - the diff stops access creep.
- **States to design:**
  - the colleague has privileged groups, which are not copied automatically and are flagged (P6);
  - the move crosses a delegation boundary and needs approval (P8);
  - an effective date set in the future.

### T11 · Add 50 users to one group (AD)

**Frequency (E; C).**
- Unknown `[UNVERIFIED]`.
- ME ships the task as a bulk modification ("change group") ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html)).

**ME flow: Group Attributes with CSV import** (bulk mod help). Totals: **≈14 I / 1 F / 5 S, plus preparing a CSV.**
1. Management tab.
2. Group Attributes.
3. "+" Add to Group.
4. Search for the group.
5. Pick it.
6. OK.
7. Import the CSV through the OS picker.
8. Choose the match attribute from a drop-down.
9. Select all.
10. Apply.

Group management is Professional-only ([pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html)). Whether this user-side path works in Standard is `[UNVERIFIED]`.

**activeDIQ flow.** Totals: **8 I / 1 F / 2 S.**
1. Press `/`.
2. Type the group.
3. Press Enter.
4. Click "Add members".
5. **Paste** 50 lines of mixed sAMAccountNames, e-mails and display names. Resolution: "48 matched · 2 ambiguous · 0 not found".
6. Pick the right match for the first ambiguous entry.
7. Pick the right match for the second.
8. Confirm. The preview reads "+48, 2 already members".

**Target: ≤ 20 s (model 17 s).**
- **Justification.** Pasting replaces building a file. Resolution shows its work, so nobody adds the wrong "J. Smith".
- **States to design:**
  - 3,000-member group: the members list is virtualised, with search inside it;
  - not-found entries are listed with copy, so the admin can chase them;
  - protected group (P6);
  - list > 5,000 lines: offer CSV.

### T12 · Change one attribute on 300 users (AD)

**Frequency (E; C).**
- Unknown `[UNVERIFIED]`. Reorganisations and office moves are the usual trigger.
- ME offers it on the Organization Attributes page and through CSV modify ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-users-modification-csv.html)).

**ME flow: Organization Attributes** (bulk mod help). Totals: **≈10 I / 1 F / 4 S.**
1. Management tab.
2. Organization Attributes.
3. Tick the attribute.
4. Type the value.
5. Add OUs through the picker.
6. Search with an empty box to list all.
7. Select all.
8. Apply.

Gaps and risks:
- Whether select-all spans grid pages for 300 users is `[UNVERIFIED]`.
- On the CSV path, ticking "clear attribute value … if empty" **wipes** values wherever a cell is blank (CSV modify help).

**activeDIQ flow.** Totals: **8 I / 3 F / 2 S.**
1. Open Users.
2. Type a filter, e.g. "department: Retail Ops".
3. Press Enter.
4. Press Ctrl+A. The banner reads "**All 300 matching selected**, not just the 50 on screen".
5. Click "Edit attribute".
6. Type the attribute, e.g. "Company".
7. Type the value.
8. Confirm the preview: "300 changes · 12 already have this value · 0 blanks will be written".

Undo is available for the batch (P5).

**Target: ≤ 25 s (model 20.8 s). Near parity on interactions; the win is a selection that cannot be misread, plus preview and undo.**
- **States to design:**
  - selection across 12,000 rows;
  - mixed current values, with a histogram in the preview;
  - an attribute the technician may not write (P8);
  - a value that fails schema syntax, caught before the write.

### T13 · Set or extend a contractor's account expiry (HD, AD)

**Frequency (B, C).**
- NIST SP 800-53 AC-2(2): disable temporary accounts automatically after a defined period ([STIG Viewer](https://www.stigviewer.com/controls/nist-800-53/AC-2(2))).
- "Set account expiry" is an ME mobile action ([help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-management/ad-management.html)).

**ME flow, single user** ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/set-ad-user-accounts-to-expire.html)). Totals: **≈15 I / 1 F / 4 S.**
1. Management tab.
2. Modify Single User.
3. Search for the user.
4. Action, then Modify User.
5. Template OK.
6. Account tab.
7. Choose "End of".
8. Use the calendar pop-up: month, day, Apply.
9. Update User.

For 20 users, ME uses the "Enable/Disable Users" page, which carries the Account Expires option: ≈16 I.

**Pain points**
- Expiry lives on a page labelled Enable/Disable.
- On the CSV path, an empty `accountExpires` with the "clear" option ticked is set to "24 hours from the time of modification" ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-users-modification-csv.html)).

**activeDIQ flow.** Totals: **6 I / 2 F / 1 S.**
1. Press `/`.
2. Type the name.
3. Press Enter.
4. Click the "Account expires" field on the user page.
5. Type "+90d" or "31 Mar". The resolved date is shown next to the input.
6. Press Enter. A toast with Undo appears.

For 20 contractors:
1. Open the saved view "Contractors expiring in 30 days".
2. Press Ctrl+A.
3. Click "Extend expiry".
4. Choose "+90 days".
5. Confirm.

That is 6 I.

**Target: ≤ 18 s (model 14 s).**
- **Justification.** The attribute is edited inline where it is displayed, and relative dates accept what admins actually say.
- **States to design:**
  - the date is in the past, so the field warns that the account will be disabled now;
  - the account has already expired and is disabled;
  - time-zone wording: AD stores the expiry as the end of a UTC day, so the field shows the local equivalent.

### T14 · Assign or change an M365 licence (AD)

**Frequency (C; E).**
- The job tracks joiners and leavers (T07, T09) by inference.
- ME offers add, replace and remove, by group or CSV ([help](https://www.manageengine.com/products/ad-manager/help/office365/management/license-management.html)).

**ME flow: Microsoft 365 tab › Assign/Remove Licenses** (licence help). Totals: **13 I / 1 F / 3 S. The M365 tab took ≈26 s to render** (ADM §4.2).
1. Microsoft 365 tab.
2. Management.
3. Assign/Remove Licenses.
4. Pick the tenant.
5. Configure Licenses.
6. Tick the licence.
7. OK.
8. Choose add, replace or remove.
9. User location.
10. Search for the user.
11. Tick the user.
12. Apply.

**Pain points**
- A separate iframe app with its own navigation (ADM §4.1).
- The help still uses "Office 365" labels.

**activeDIQ flow.** Totals: **6 I / 1 F / 2 S.**
1. Press `/`.
2. Type the user.
3. Press Enter.
4. In the Licences section, click "Assign".
5. Pick a SKU. The list shows free seats, e.g. "E3 · 12 of 250 free".
6. Confirm.

If `usageLocation` is missing, it is set inline in the same sheet, because Graph requires it before a licence can be assigned ([MS Learn](https://learn.microsoft.com/en-us/graph/api/user-assignlicense)).

**Target: ≤ 18 s (model 14.4 s).**
- **Justification.** AD and cloud live on one object page (ENH "one console").
- **States to design:**
  - no seats left;
  - the licence comes from a group (group-based licensing), shown as inherited and not removable here, with a link to the group;
  - service-plan toggles collapsed by default;
  - a Graph throttling retry with a visible status.

### T15 · Restore a user deleted by mistake (AD)

**Frequency (E).**
- Rare, and high-stakes `[UNVERIFIED]`.
- ME has a KB article for it ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/how-to-restore-deleted-active-directory-users.html)).

**ME flow: Management › Restore Deleted Users, under Bulk User Modification** (KB). Totals: **9 I / 1 F / 3 S.**
1. Management tab.
2. User Management.
3. Restore Deleted Users.
4. Domain.
5. Type the name.
6. Search.
7. Tick the user.
8. Apply.

Group memberships come back only if the AD Recycle Bin was enabled **before** the deletion ([MS Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)). Fuller recovery needs the paid Backup add-on or RecoveryManager Plus ([FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html)).

**activeDIQ flow.** Totals: **5 I / 1 F / 2 S.**
1. Press `/`.
2. Type the name. Deleted objects show in the results with a chip: "Deleted 1 Oct 16:42 by svc-hr-sync".
3. Press Enter.
4. Click "Restore". The preview reads: "to `OU=Sales,…` · 12 group memberships restored (Recycle Bin on) · password must be reset".
5. Confirm.

The deletion also appears in "Recent changes" with an Undo (P5).

**Target: ≤ 15 s (model 13.1 s).**
- **Justification.** The deleted object is found where people look, by search, and not under "Bulk User Modification".
- **States to design:**
  - Recycle Bin off: the preview lists what **cannot** be restored, and what activeDIQ can re-apply from its own change history;
  - the original OU has since been deleted;
  - the name or UPN is now taken by someone else;
  - beyond the tombstone or recycled lifetime.

### T16 · Who removed X from Domain Admins, and when (SEC, AD)

**Frequency (B, C).**
- PCI DSS 10.4.1 requires daily review of security-event logs, and 10.2.1.5 requires logging privilege elevation ([MS Learn PCI 10](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-10)).
- ME sells alerting for privileged-group changes ([ADAP alerts](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html)).
- The investigation itself is event-driven.

**ME flow: ADAudit Plus, a separate product** ([how-to](https://www.manageengine.com/products/active-directory-audit/how-to/how-to-track-changes-in-active-directory-groups.html)). Totals: **11 I / 1 F / 2 S**, plus one-time DC audit-policy and event-log setup ([audit policy](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-audit-policies-manually.html); [event log](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-event-log-settings.html)).
1. Reports.
2. Domain.
3. Group Management.
4. "Recently Removed Members from Security Groups".
5. Period.
6. Generate.
7. Search for the member.

ADAudit Plus build 9000 renamed its paths ([RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html)), so the labels are `[UNVERIFIED]`.

**ADManager Plus alone cannot answer this** for changes made outside it:
- History lists changes made "using ADManager Plus" ([help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html));
- the technician audit report covers technicians' actions in ADMP ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-technician-audit-report.html)).

**activeDIQ flow.** Totals: **5 I / 2 F / 1 S.**
1. Press `/`.
2. Type "domain admins".
3. Press Enter.
4. Open the History tab.
5. Type the member's name in the filter. The row reads: "**Removed** Priya Raman · by `CORP\j.ops` from `ADM-WS-07` · 1 Oct 22:14 · via ADUC (DC event 4729)".

Event 4729 is "A member was removed from a security-enabled global group" ([MS Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)). From the row, the admin can **revert** (re-add, with the P6 confirmation).

**Target: ≤ 15 s (model 12.7 s).**
- **Justification.** One console answers it, from the group's own page.
- **Dependency, and the stale-data state.** "Who" needs DC security-event collection (Phase 2), and ADAudit-parity reporting is a later milestone (D-0001). Changes made through activeDIQ are always attributed. Before event collection exists, the row shows **when, and on which DC**, from linked-value replication metadata ([MS Learn, msDS-ReplValueMetaData](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-replvaluemetadata)), and says "who: needs DC event collection". The ad-expert should confirm the LVR detail in T-0009 review.
- **States to design:**
  - removed and re-added several times;
  - change made by a service account;
  - events past retention.

### T17 · Clean up stale computers: 90 days → disable → quarantine → delete (AD)

**Frequency (B).**
- Microsoft's guidance is not to treat devices active within 21 days as stale. Its example disables devices after 90 days and deletes them after 120 ([MS Learn](https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices)).
- In practice this runs monthly to quarterly (inference).

**ME flow, one-off cleanup over two visits** ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/find-and-remove-inactive-ad-computers.html)). Totals: **36 I / 0 F / 8 S.**
- **Visit 1** (20 I / 5 S):
  1. Reports.
  2. Computer Reports.
  3. Inactive Computers. The period defaults to **"Last 30 days"**, served from a cached run dated 6 days earlier `[demo]` ([me-09](top-admin-tasks-benchmark-evidence/me-09-inactive-computers-report.png)).
  4. Set the period to 90 days.
  5. Generate.
  6. Check all.
  7. Disable.
  8. Confirm.
  9. Check all again.
  10. Move.
  11. Pick the OU.
  12. Confirm.
- **Visit 2, weeks later** (16 I / 3 S): regenerate the report on the quarantine OU, then Check all, Delete and Confirm.

**ME automated path** (Professional only): an automation policy plus an automation take ≈45 I over 6 S of one-time setup ([use case](https://www.manageengine.com/products/ad-manager/help/automation/usecase2-automation.html); [policy](https://www.manageengine.com/products/ad-manager/help/automation/configuring-automation-policy.html)).

**Pain points**
- No undo is documented.
- There is no named exclusion list, only conditions.
- Last Logon shows a raw `0` (me-09).

**activeDIQ flow.** Totals: **8 I / 1 F / 3 S.**
1. Open "Clean up".
2. Open the "Stale computers" card. It reads, for example, "1,284 inactive > 90 days · servers excluded". Each row shows `lastLogonTimestamp` **and** `pwdLastSet`, with ±14-day wording (see T03).
3. Press Ctrl+A.
4. Click "Quarantine". The plan reads: "disable now → move to `OU=Quarantine` → delete after 30 days, with a digest 3 days before".
5. Turn on "Repeat monthly".
6. Type the count as the deliberate confirmation for more than 100 objects.
7. Confirm.

Undo covers disable and move (P5). **Visit 2 is the digest** (2 I: open it, approve). That replaces both the second visit and ME's 45-interaction automation setup.

**Target: ≤ 30 s (model 19.4 s).**
- **Justification.** This is the brief's own example job.
- The two visits and the automation setup collapse into one plan with a schedule. The safeguards stay, because quarantine comes before delete and big batches need deliberate confirmation.
- **States to design:**
  - **12,000-row result** at 1,284 selected;
  - the exclusion list (OU, name pattern, OS = server, "do not touch" tag);
  - a computer that becomes active during quarantine is auto-restored and reported;
  - a BitLocker key on a computer about to be deleted shows a warning, and keys are kept;
  - a cluster or virtual computer object (CNO/VCO) is excluded by default.

### T18 · Clean up inactive users, excluding service accounts (AD, CMP)

**Frequency (B).**
- CIS v8 5.3: disable dormant accounts after **45 days** ([CIS](https://controls-assessment-specification.readthedocs.io/en/latest/control-5/control-5.3.html)).
- PCI DSS 8.2.6: **90 days** ([MS Learn PCI 8](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-8)).

**ME flow** ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/find-and-delete-inactive-ad-user-accounts.html)). Totals: **39 I / 1 F / 9 S** over two visits.
1. Reports.
2. User Reports.
3. Inactive Users.
4. Set 90 days.
5. Tick "Exclude disabled".
6. Generate.
7. Filter service accounts **by hand**. The KB says to "explicitly exclude service accounts", and the filter on this report is `[UNVERIFIED]`.
8. Disable.
9. Move.
10. Later, delete.

**Pain points**
- Users who sign in over VPN can show as inactive ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html)).
- No service-account detection.

**activeDIQ flow.** Totals: **10 I / 1 F / 3 S.** This is the T17 flow plus a "Probably service accounts (37)" group, excluded by default and listed with the reason for each. Signals include:
- `servicePrincipalName` set;
- gMSA or sMSA object class;
- "password never expires" combined with no interactive sign-in;
- naming patterns.

Reviewing that group costs 2 I.

**Target: ≤ 45 s (model 22 s, plus review time).**
- **Justification.** The dangerous part (killing a service account) is handled by default, with the evidence shown.
- **States to design:**
  - sign-in data from Entra (cloud-only activity) shows the user as active, and both sources are displayed;
  - the user is on leave, via an exclusion tag;
  - the user owns a mailbox shared by others.

### T19 · Export Domain Admins membership, nested, for an auditor (CMP, SEC)

**Frequency (B).**
- PCI DSS 7.2.4: review accounts and privileges "at least once every six months" ([MS Learn PCI 7](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-7)).
- A quarterly SOX cadence is common practice, not law ([Lumos](https://www.lumos.com/identity-matters/identity-access-management/how-to-automate-sox-user-access-reviews)) `[UNVERIFIED as a rule]`.

**ME flow: Group Reports › Detailed Group Members** ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-group-reports.html); [page](https://www.manageengine.com/products/ad-manager/active-directory-group-membership-report.html)). Totals: **13 I / 1 F / 3 S.**
1. Reports.
2. Group Reports.
3. Detailed Group Members.
4. Domain.
5. Use the group picker: type, search, select, OK.
6. Generate.
7. Export as PDF.

**Pain points**
- The report is not named "nested". The admin has to know it is the one.
- "Reporting is Strong but Sometimes Slow" ([Capterra, Goutam D., 2025-12-09](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/)).

**activeDIQ flow.** Totals: **6 I / 1 F / 1 S.**
1. Press `/`.
2. Type "domain admins".
3. Press Enter.
4. On the Members tab, toggle "**Effective (nested) · 11**" (the direct count is 4).
5. Click Export.
6. Choose PDF.

The export is an **evidence pack**:
- the effective-membership path for each member (via which group);
- generated by and at;
- the data freshness time;
- a hash.

**Target: ≤ 15 s (model 12 s).**
- **Justification.** Auditors ask for "who has Domain Admin", not for a report name. The evidence pack answers their next question too ("how do they have it?").
- **States to design:**
  - circular nesting is detected and shown;
  - a foreign security principal from a trusted forest;
  - disabled members, which still count and are flagged;
  - data older than the last sync, which shows its age.

### T20 · Schedule a monthly compliance report by e-mail (CMP)

**Frequency (B, C).**
- The schedule is set up rarely and then runs monthly.
- PCI DSS 10.4.1 sets daily log review ([MS Learn PCI 10](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-10)).
- ME schedules run hourly to monthly ([help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-scheduled-reports.html)).

**ME flow: Reports › Schedule Reports, Professional only** ([pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html)). Totals: **19 I / 2 F / 4 S.**
1. Reports.
2. Schedule Reports.
3. New.
4. Name.
5. Domain.
6. Report picker: category, report, OK.
7. Monthly, day and time.
8. Format.
9. Recipient.
10. Save.

All of these steps are `[doc]`/`[inferred]`.

**Pain points**
- Scheduling is not in Standard.
- Report UX is the #2 complaint theme (≈17 reviews, CV X2), e.g. "custom reports … can overflow from the container" ([Capterra, Jacob M., 2026-09-15](https://www.capterra.com/p/143496/ADManager-Plus/reviews/)).

**activeDIQ flow.** Totals: **7 I / 2 F / 2 S.**
1. Press `/`.
2. Type "password never expires".
3. Press Enter. The report opens with results.
4. Click "Schedule" in the report header.
5. Pick a preset: "Monthly · 1st · 08:00".
6. Type the recipient.
7. Save. PDF is the default format.

**Target: ≤ 25 s (model 17.6 s).**
- **Justification:**
  - the admin schedules from the report they are looking at;
  - presets cover the common cadences;
  - scheduling is in every tier (`product-strategy.md`: one licence).
- **States to design:**
  - "send only if there are results";
  - the recipient is outside the organisation's domains, which needs confirmation because data leaves the building;
  - a delivery failure is shown on the schedule;
  - an empty report.

## 4. Cross-cutting patterns the targets depend on

These patterns are inputs to T-0009 (IA) and the design system (T-0043). If a pattern is dropped, the targets of the tasks that depend on it must be re-baselined.

| # | Pattern | Tasks that depend on it |
|---|---|---|
| **P1** | **One search, every identifier.** `/` or Ctrl+K from anywhere. It matches sAMAccountName, UPN, display name, e-mail, employee ID, computer name, BitLocker key ID and group name, and it includes deleted objects. Results carry **status chips**, so many questions are answered without opening anything. Enter opens a deep-linkable object page. | All except T08 |
| **P2** | **The object page is the workspace.** Status, memberships (direct and effective), devices, licences and the History tab ("who/what/when", P5) live on one page. Contextual primary action: a locked account offers "Reset & unlock" first. Each action has a single-key shortcut. **No modal stacks:** at most one side sheet. | T01–T07, T09, T10, T13–T16, T19 |
| **P3** | **Preview before write.** Every change sheet shows exactly what will change: counts, named objects, and side effects such as nesting and licences. Bulk previews summarise first ("300 changes · 12 unchanged"), then list. | T06–T12, T15, T17, T18 |
| **P4** | **Bulk equals single.** Every single action also accepts a selection (filter + Ctrl+A meaning *all matching*, stated in words), a pasted list, or a file. Lists resolve visibly: matched, ambiguous, not found. | T08, T11–T13, T17, T18 |
| **P5** | **Undo and an audit line after every change** (ENH-04). A toast with Undo, for a period set by policy where the operation is reversible. Every change lands in the object's History and in Recent changes as who, what, when and how. Irreversible operations (password, delete past quarantine) say so in the sheet. | All writes |
| **P6** | **Privileged and destructive friction scales with impact.** Protected and Tier-0 groups, admin accounts, more than 100 objects, and delete all need **typed confirmation** (the count, or the object name), plus an approver where policy demands. Ordinary edits get one Confirm. | T01, T06, T09, T10, T17, T18 |
| **P7** | **Long work runs in the background with honest progress.** Bulk creates, cleanups and big reports never block the console. Partial failure is a designed state: "N of M done, K failed, here is why", with Retry failed, Export failures and Undo batch. | T08, T11, T12, T17, T18 |
| **P8** | **Permission-aware, not permission-hidden.** Out-of-scope objects and actions are visible but disabled, with the reason and who can help. Nothing silently disappears. | All |

**Self-service is out of scope here.** The end-user persona's jobs (reset my own password, unlock myself, update my profile) are ADSSP-parity work in a later milestone (D-0001). They will get their own mobile-first benchmark. Its prerequisite is ENH-03, enrolment without blocking.

## 5. Measurement protocol: how these targets get verified

1. **activeDIQ side.** Once screens exist, script each task in Playwright against the AD lab (T-0012, plus a seeded 12,000-user tier, T-0049). For each task, count I, F and S, and record wall-clock time with the budgets above. A design review or QA fails a flow that exceeds its interaction budget or misses its time target by more than 20%. This is automated by T-0063.
2. **ME side.** Re-run the T01, T07, T08, T17 and T19 paths on a **local ME evaluation install**, so we get waits without network distance. Then close the `[UNVERIFIED]` items in §6. We will not quote ME waits externally before this is done (ADM §4.2 `[TODO]`). The evaluation download needs registration under a skenzeriq identity, which is an external action. T-0062 does this and must get CEO approval through `ceo-decisions` before it registers.
3. **Pilot side.** Five representative tasks (T01, T03, T08, T09, T17) are timed with real admins at a warm account, in both tools. This feeds the proof point "task-time benchmarks on 10 tasks from customer pilots" (`product-strategy.md`).

## 6. Open items

- `[UNVERIFIED]` ME flows that the docs do not settle:
  - T01: the console's unlock behaviour when the account is not locked;
  - T03: whether the object Properties page shows lock, expiry and last logon together;
  - T04: the build-8030 BitLocker "dedicated interface";
  - T05: any LAPS reveal or masking;
  - T08: per-row failure reasons and retry in place;
  - T09: whether the disable policy can convert an Exchange Online mailbox to shared;
  - T10: whether "Copy User Attributes" copies `memberOf`, and whether it appends or replaces;
  - T11: Group Attributes in Standard;
  - T12: select-all across pages;
  - T16: ADAudit Plus 9000 labels;
  - T17, T18: the bulk Disable and Move menu labels.
- `[UNVERIFIED]` Frequency for T02, T05, T08, T10–T12 and T15. These are replaced by pilot ticket data when it exists.
- `[UNVERIFIED original]` Gartner's "20–50%" and Forrester's "$70 per reset" are quoted second-hand (TechTarget 2011; The Hacker News 2021). Do not use them in external material without the originals.
- `[TODO]` Self-service (end-user) benchmark, when ADSSP parity is scheduled.
- **Runtime targets** for T08 (validation ≤ 10 s, create ≤ 120 s for 200) and the ≤ 1 s per-screen budget are **design budgets**. The directory-engineer and the solution-architect must confirm them against the AD lab before they go into a spec's acceptance criteria.

## Changelog

- 2026-10-02 · product-designer (T-0008) · First version. 20 tasks benchmarked from:
  - a read-only walk of the ME public demo (build 8041);
  - ME docs;
  - the research corpus.
  
  Targets were set with the KLM model.
