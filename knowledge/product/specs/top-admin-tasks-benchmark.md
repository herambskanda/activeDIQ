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
- how ME does it today, step by step, with a count and a source for each step;
- what hurts, with sources;
- the budget activeDIQ must meet: interactions, screens and time.

T-0009 (information architecture) must give every task a path within its budget. Later design and QA tickets measure against the same numbers, and T-0063 automates the check using the rules in §1.2.

**What it is not.** These are not measured activeDIQ times; no activeDIQ code exists yet. The ME times are a model plus indicative waits from the public demo. They are not a stopwatch on a customer install. Nothing here may be quoted externally until §5 has been run (CV §6.2, ADM §4.2 `[TODO]`).

**Evidence base**
- **Our own read-only walks of ME's public demo:** ADManager Plus Professional, build 8041, on 2026-10-02. We clicked through but submitted nothing. Screenshots are in [`top-admin-tasks-benchmark-evidence/`](top-admin-tasks-benchmark-evidence/) (me-01 … me-12).
- **ME help docs and KB articles**, linked inline.
- **Re-total script:** [`klm.py`](top-admin-tasks-benchmark-evidence/klm.py) recomputes every figure in §2 from the per-task counts.
- **Abbreviations for internal sources:**
  - `ADM` = `knowledge/business/market-research/manageengine-admanager-plus.md`
  - `ADSS` = `knowledge/business/market-research/manageengine-adselfservice-plus.md`
  - `CV` = `knowledge/business/market-research/manageengine-ad-customer-voice-and-security.md`
  - `LAND` = `knowledge/business/competitive-analysis/ad-management-market-landscape.md`
  - `ENH` = `knowledge/business/strategy/enhancement-catalog.md`
  - `TM` = `knowledge/development/architecture/threat-model.md`
- **Product abbreviations:** ADMP = ADManager Plus, ADAP = ADAudit Plus, ADSSP = ADSelfService Plus.

## Key takeaways

1. **The gap is in the jobs ME splits across screens, products or visits.** These are the interaction and modelled-time cuts:

   | Task | Interactions | Modelled time |
   |---|---|---|
   | T09 offboard a leaver | −71% | −60% |
   | T10 mover | −69% | −60% |
   | T18 inactive users, two visits | −62% | −50% |
   | T17 stale computers, two visits | −58% | −44% |
   | T02 lockout source, two products | −50% | −49% |
   | T16 privileged-group forensics, separate product | −44% | −20% |

2. **On single-object help-desk jobs, ME's click count is already low, and on five tasks we are not faster in the model:**
   - T01 with caller verification (+13%);
   - T04 BitLocker (+14%);
   - T05 LAPS (+99%);
   - T12 (−1%) and T15 (0%), which are parity.

   T01, T04 and T05 are slower because we add deliberate security steps: caller verification, a reveal reason, and the step-up MFA our threat model requires (TM §7.4, TM-D16). On these jobs our edge is elsewhere:
   - **No page loads.** The demo's Reset Password Console took **14.5 s** to open, and the dashboard took **23.8 s**.
   - **Safe defaults.** ME's bulk reset form defaults to **"Same as logonname"**, and "must change at next logon" is unticked in the console.
   - **Status at a glance.** ME's search results show names only, with no locked, disabled or expired status.
   - **Audit in the same product.** ME audits LAPS reads only in ADAudit Plus.

   We do not claim a time win where there isn't one.
3. **Bulk jobs fail on data handling, not clicks.** ME's CSV import has three problems:
   - It needs LDAP attribute names as headers, the OU as a quoted DN, and all three country attributes (`c`, `co`, `countryCode`).
   - Its own guidance disagrees on how to name a group or manager. The format page accepts a DN, sAMAccountName, display name or e-mail. The in-product hint says "DN format or Sam Account Name" only (T08).
   - Per-row failure reasons and retrying only the failed rows are not documented.

   Our target is to accept an HR export as-is, validate every row before writing, and support "Retry 13 failed".
4. **Three enhancements add steps on purpose:**
   - caller verification on reset (ENH-09, +2 interactions);
   - a reason on LAPS and BitLocker reveal (+1);
   - step-up MFA on those reveals (TM-D16, +1 interaction and +1 screen when outside the step-up window).

   Each is justified in its task. A tier-1 agent who resets a password for an unverified caller is the initial vector in documented attacks ([CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a); [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)).
5. **Totals across all 20 tasks.** Both time columns are modelled interaction time **without waits on either side** (§1.3):

   | | ME | activeDIQ target |
   |---|---|---|
   | Interactions | 278 | 138 (−50%) |
   | Typed fields | 25 | 36 |
   | Screens | 77 | 56 (−27%) |
   | Modelled time, wait-free | ≈513 s | ≈323 s (−37%) |
   | activeDIQ with its wait budget (≤ 1 s per screen) | — | ≈379 s |

   ME's own waits come on top of its ≈513 s. On the demo, a single page load took 14.5–22.6 s (§1.5).

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

**T15 (restore a deleted user) and T20 (set up a scheduled report) are rare.** They are included for their stakes, not their frequency. A slow or wrong restore is an outage, and a broken schedule is an audit finding.

Jobs considered and left out are:
- delegating reset rights for an OU (a one-time setup);
- pre-staging a computer;
- GPO edits;
- NTFS permission changes (lower frequency, and not in the brief).

### 1.2 Counting rules (applied to both products)

These rules are literal so that T-0063 can implement them. Each task's flow tables in §3 apply them row by row.

**Start and end state**
- **Start state:**
  - logged in, on the home screen;
  - knows the target's name;
  - one domain and one M365 tenant, so domain and tenant selectors are left at their preselected value (observed on the demo: [me-10](top-admin-tasks-benchmark-evidence/me-10-bitlocker-recovery-keys.png), [me-12](top-admin-tasks-benchmark-evidence/me-12-group-attributes.png)). A multi-domain install adds 2 interactions to most ME flows.
- **Multi-visit tasks** (T17, T18): each visit starts again from the home screen.
- **End state:** the change is committed, or the answer is on screen. The final confirmation (toast, status step, result page) is **not** counted as a screen.

**Interactions (I).** Each of these counts as 1:
- a click on a tab, link, menu, button, checkbox or radio;
- selecting a list item;
- one keyboard shortcut (`/`, `R`, `Ctrl+A` …) or Enter;
- typing into one field, whatever its length;
- pasting a list.

Some acts count differently:
- A drop-down = 2 (open, pick).
- An OS file picker = 2 (open it, choose the file) + 1 screen. Dropping a file = 1, with no screen.
- A field or option left at its default = 0.
- Reading or reviewing = 0. Time for reading is covered by the screen term and the headroom in §1.3.

**Typed fields (F).** Every typed field is also counted in F, because typing dominates time.

**Screens (S).** Each of these counts as 1 screen:
- a page load or route change, including a top-level tab's landing page (ME's Management or Reports tab);
- a modal, pop-up, picker dialog, confirmation dialog, date-picker pop-up or side sheet that opens;
- **activeDIQ's `/` search overlay**, because it is a pop-up that opens over the page;
- activeDIQ's step-up MFA prompt;
- an OS file picker.

None of these is a screen; each costs only its interactions:
- in-place refresh of a grid, list or report on the same page (search results, filters, Generate);
- a type-ahead suggestion list attached to a field;
- switching an in-page tab (ME's Account or Contact tab; our History or Members tab), even if the URL changes;
- expanding a panel or an inline chooser;
- ME's sub-navigation menus and left-pane categories ("Computer Reports ▾", "Group Management"). These are 1 interaction each.

**Unknowns favour ME.** Where we could not tell whether a ME step loads a new page, no screen is counted. Where ME's selection might reset after an action, we assume it persists. Switching between ME products (T02) is not counted.

**Standard ME pickers.** These are used wherever ME opens one:
- **Object picker** (group, manager): "+" opens a pop-up (1 I, 1 S), then type the name (1 I, 1 F), Search (1), select (1), OK (1). Total **5 I / 1 F / 1 S**.
  - The "+" pop-up is observed on the demo ([me-11](top-admin-tasks-benchmark-evidence/me-11-create-user-contact-tab.png), me-12).
  - The help says "Select the group from popup … click Ok" ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html)).
  - The search step inside is `[inferred]`: the demo's group pop-up did not finish loading in our 40 s window (§1.5).
- **OU picker:** "+" or "Add OUs" (1 I, 1 S), then expand the domain (1), select the OU (1), OK (1). Total **4 I / 0 F / 1 S**, `[inferred]`.

**Source tags.** Each ME step carries one:
- `[demo]`: observed by us on 2026-10-02;
- `[doc]`: stated in the ME page cited in that task's heading;
- `[inferred]`: deduced from docs and screenshots.

ME counts are for the **shortest documented path** in the edition that has the feature. A prepared template is assumed where ME needs one, and any one-time setup is listed separately, outside the totals.

### 1.3 Time model

Time is modelled with the Keystroke-Level Model ([Card, Moran & Newell 1980](https://doi.org/10.1145/358886.358895); [summary](https://en.wikipedia.org/wiki/Keystroke-level_model)). The operator values are:
- P point = 1.1 s;
- B click = 0.2 s;
- H home hands = 0.4 s;
- K keystroke = 0.28 s;
- M mental preparation = 1.35 s.

They are simplified into one formula, used for both products:

> **T = 1.3 s × (I − F) + 3.2 s × F + 1.35 s × S**

The components are:
- **1.3 s** = P + B per non-typed interaction. Keyboard shortcuts are also priced at 1.3 s, which is conservative and works against us.
- **3.2 s** = H + ≈10 characters × K per typed field.
- **1.35 s** = one M to orient on each new screen.

**T is wait-free.** It never includes system response time, for either product. The §2 totals and every "−x%" in this document compare wait-free T with wait-free T.

**Waits (W) are separate:**
- **ME's waits** are the demo timings we measured (§1.5). They are indicative only, because the demo is shared and remote.
- **activeDIQ's wait budget** is **1 s per screen**, as p95 on the reference install. This is a **performance requirement**, and it is owned by the architecture (T-0004 follow-ups).
- **Long-running work** (bulk writes, reports over 12,000+ objects) gets its own runtime target. It runs in the background with progress, so it never blocks the admin's next task.

**The target rule.** Each task's target is:

> **Target = ⌈ 1.1 × (T + 1 s × S) ⌉ seconds**

That is the modelled time plus the wait budget, with 10% headroom for reading and checking, rounded up to a whole second.

Each task in §3 states it in that form, for example "model 17.0 s + 3 s wait budget = 20.0 s → ≤ 22 s". The interaction budget is the activeDIQ I count, and it is a hard limit. The point of a target is to fail a design that misses it.

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
| Reset pop-up | "Type a password" preselected, "Generate password" offered. "User must change the password at next logon" **unticked**. "Account is locked out" is a checkbox, so unlock is part of the same pop-up. No caller-verification step | [me-03](top-admin-tasks-benchmark-evidence/me-03-helpdesk-reset-popup.png) |
| Header search "Search AD Objects" | Opens a **report** ("Search Users, Groups, Computers & Contacts") in ≈6 s. Result columns: SAM, Last, First, Common and Display Name. **No status** | [me-04](top-admin-tasks-benchmark-evidence/me-04-global-search-results.png) |
| Management › User Management landing | **87 links** on one page | [me-05](top-admin-tasks-benchmark-evidence/me-05-management-user-landing.png) |
| Management › Reset Password (bulk form) | Default **"Same as logonname"**. "Must change at next logon" is a drop-down set to **N/A** | [me-06](top-admin-tasks-benchmark-evidence/me-06-management-reset-password.png) |
| Create Single User | Full page reload, **16.1 s**. "Select Template" drop-down defaults to "System Template". 3 required fields on the General tab; "Select Container" defaults to `CN=Users` with a "+" picker | [me-07](top-admin-tasks-benchmark-evidence/me-07-create-single-user.png) |
| Create Single User › Contact tab | Title and Department are drop-downs. **Manager** is a read-only field with a "+" picker | [me-11](top-admin-tasks-benchmark-evidence/me-11-create-user-contact-tab.png) |
| Create Bulk Users | Full page reload, **22.6 s**. A 3-step wizard: "Add user details" → "Choose Container" → "Creation and Status". On-page hint, verbatim: "Specify memberOf, manager in DN format or Sam Account Name and ouName in DN format enclosed by double quotes." | [me-08](top-admin-tasks-benchmark-evidence/me-08-create-bulk-users.png) |
| Group Attributes (bulk) | "Add to group" and "Remove from group", each with a "+" pop-up. Domain preselected. "Find the users": "Enter name(s) to search" (preselected) or "CSV Import". Hint: "Leave this field blank to see all" | [me-12](top-admin-tasks-benchmark-evidence/me-12-group-attributes.png) |
| Group picker pop-up | Opened, but did **not finish loading within 40 s** in our single attempt. The time is not used anywhere; its contents are `[inferred]` | — |
| Inactive Computers report | Default period **"Last 30 days"**. Results served from a cached run ("Generated on 2026-09-24"). Last Logon Time shows a raw `0`. Toolbar: Delete, Disable, Move, "…", Create Request | [me-09](top-admin-tasks-benchmark-evidence/me-09-inactive-computers-report.png) |
| BitLocker Recovery Keys | A domain-wide **report** that must be generated. The domain checkbox is pre-ticked. There is no single-computer or key-ID lookup field | [me-10](top-admin-tasks-benchmark-evidence/me-10-bitlocker-recovery-keys.png) |

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
- **I/F/S** = interactions / typed fields / screens (§1.2).
- **ME T** = modelled time, wait-free (§1.3).
- **ME W** = demo-observed waits on the path, where we measured them.
- **aDIQ T + W** = our modelled time plus the 1 s/screen wait budget.
- **Target** = ⌈1.1 × (T + W)⌉, which design and QA must meet. The aDIQ I count is the interaction budget.

| ID | Task | Persona | Frequency (class) | ME path (product · edition) | ME I/F/S | ME T | ME W | aDIQ I/F/S | aDIQ T + W | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| T01 | Reset password + unlock for a caller | HD | Daily, many per day (A, C) | ADMP Reset Password Console · Std+Pro | 8/1/2 | 15.0 s | 14.5 s + search | 7/2/3 (5/1/3 without verification) | 17.0 + 3 | **≤ 22 s** (≤ 17 s) |
| T02 | Find a repeated lockout's source, then unlock | HD | Weekly–daily (B, C; E) | ADAP Lockout Analyzer (**Pro**) + ADMP Unlock Users · **2 products** | 10/1/5 | 21.7 s | n/m | 5/1/2 | 11.1 + 2 | **≤ 15 s** |
| T03 | Look up a caller's account status | HD | Daily, before most T01/T02 (C) | ADMP search + AD Explorer · Std+Pro | 8/1/2 | 15.0 s | ≈6 s search | 3/1/2 | 8.5 + 2 | **≤ 12 s** |
| T04 | Retrieve a BitLocker recovery key | HD | Occasional, with incident spikes (C) | ADMP BitLocker report · Std+Pro | 7/1/2 | 13.7 s | report run | 6/2/3 (5/1/2 in step-up window) | 15.7 + 3 | **≤ 21 s** (≤ 15 s) |
| T05 | Retrieve a LAPS password | HD, AD | Weekly (C; E) | ADMP AD Explorer · n/s | 5/0/1 | 7.8 s | n/m | 6/2/3 (5/1/2 in step-up window) | 15.7 + 3 | **≤ 21 s** (≤ 15 s) |
| T06 | Add a user to a group | HD, AD | Daily–weekly (B, C) | ADMP Group Attributes · Std+Pro | 11/2/3 | 22.2 s | picker > 40 s once (not used) | 7/2/3 | 17.0 + 3 | **≤ 22 s** |
| T07 | Create one joiner (manager, mailbox, licence, groups) | AD | ≈33 / 1,000 staff / month (A) | ADMP Create Single User + prepared template · Std+Pro | 13/3/3 | 26.7 s | 16.1 s | 6/3/1 | 14.9 + 1 | **≤ 18 s** |
| T08 | Bulk-create 200 users from CSV | AD | Seasonal / event-driven (E) | ADMP Create Bulk Users · Std+Pro | 12/0/4 + CSV rework | 21.0 s | 22.6 s | 6/0/3 | 11.9 + 3 | **≤ 17 s** of interaction; 200 rows validated ≤ 10 s, created ≤ 120 s |
| T09 | Offboard a leaver | AD | ≈33 / 1,000 staff / month (A, B) | ADMP Enable/Disable Users + policy + M365 Mailbox Conversion · Std+Pro | 17/2/4 (+12 I setup) | 31.3 s | M365 tab ≈26 s | 5/1/3 | 12.5 + 3 | **≤ 17 s** |
| T10 | Process a mover (title, department, manager, groups, OU) | AD, HD | Unknown (E; B) | ADMP Modify Single User + Move Users · Std+Pro | 36/5/10 | 69.8 s | n/m | 11/5/3 | 27.9 + 3 | **≤ 34 s** |
| T11 | Add 50 users to one group | AD | Unknown (E; C) | ADMP Group Attributes + CSV · Std+Pro `[UNVERIFIED Std]` | 15/1/4 + CSV | 26.8 s | n/m | 8/1/3 | 16.4 + 3 | **≤ 22 s** |
| T12 | Change one attribute on 300 users | AD | Unknown (E; C) | ADMP Organization Attributes · Std+Pro | 11/1/3 | 20.2 s | n/m | 9/3/2 | 20.1 + 2 | **≤ 25 s** |
| T13 | Set or extend a contractor's expiry | HD, AD | Unknown (B, C) | ADMP Modify Single User › Account · Std+Pro | 13/1/5 | 25.6 s | n/m | 6/2/2 | 14.3 + 2 | **≤ 18 s** |
| T14 | Assign an M365 licence | AD | Tracks T07/T09 (C; E) | ADMP M365 tab › Assign/Remove Licenses · Std+Pro | 12/1/3 | 21.6 s | ≈26 s tab | 6/1/3 | 13.8 + 3 | **≤ 19 s** |
| T15 | Restore a user deleted by mistake | AD | Rare; included for stakes (E) | ADMP Restore Deleted Users · Std+Pro (needs Recycle Bin) | 6/1/2 | 12.4 s | n/m | 5/1/3 | 12.5 + 3 | **≤ 17 s** |
| T16 | Who removed X from Domain Admins, and when | SEC, AD | Logs reviewed daily; investigations on events (B, C) | **ADAudit Plus** group report · separate product | 9/1/2 (+ DC audit setup) | 16.3 s | n/m | 5/2/2 | 13.0 + 2 | **≤ 17 s** |
| T17 | Clean up stale computers (90 d → disable → quarantine → delete) | AD | Monthly–quarterly (B) | ADMP Inactive Computers report, 2 visits · Std+Pro | 26/0/8 | 44.6 s | report run | 11/2/5 | 24.9 + 5 | **≤ 33 s** |
| T18 | Clean up inactive users, excluding service accounts | AD, CMP | Every 45–90 days (B) | ADMP Inactive Users report, 2 visits · Std+Pro | 34/0/8 | 55.0 s | report run | 13/2/5 | 27.5 + 5 | **≤ 36 s** |
| T19 | Export Domain Admins membership, nested, for an auditor | CMP, SEC | Every 6 months (PCI) to quarterly (B) | ADMP Detailed Group Members report · Std+Pro | 11/1/3 | 20.2 s | report run | 6/1/2 | 12.4 + 2 | **≤ 16 s** |
| T20 | Schedule a monthly compliance report by e-mail | CMP | Set up rarely, runs monthly; included for stakes (B, C) | ADMP Schedule Reports · **Pro** | 14/2/3 | 26.1 s | n/m | 7/2/3 | 17.0 + 3 | **≤ 22 s** |
| | **Total** | | | | **278 / 25 / 77** | **≈513 s wait-free** | | **138 / 36 / 56** | **≈323 s wait-free; ≈379 s with wait budget** | |

*n/m = not measured on the demo.* The totals count T01 with verification and T04/T05 outside the step-up window.

**Five tasks are not a modelled-time win**, and the summary should not suggest otherwise:
- **T01 with verification:** 17.0 s vs 15.0 s, because of two deliberate verification steps. Without verification we are at 12.5 s.
- **T04:** 15.7 s vs 13.7 s, because of the reason and step-up MFA.
- **T05:** 15.7 s vs 7.8 s. ME's tree browse needs no typing, and we add search, the reason and step-up MFA.
- **T12:** 20.1 s vs 20.2 s, which is parity.
- **T15:** 12.5 s vs 12.4 s, which is parity.

On these tasks we win on waits, safety, defaults, previews and audit, not on clicks. Each task section says which.

## 3. Task detail

Every task follows the same structure:
- frequency evidence;
- the ME flow table, with I/F/S and a source tag for every step (§1.2);
- pain points;
- the activeDIQ flow table;
- the target, with its arithmetic and justification;
- the states the design must cover.

The activeDIQ flows rely on the shared patterns in §4 (P1–P8).

### T01 · Reset password + unlock for a caller (HD)

**Frequency (A, C).**
- Password resets are "20% to 50% of all help desk calls", attributed to Gartner ([TechTarget, 2011](https://www.techtarget.com/enterprise-software/tip/Resetting-passwords-in-the-enterprise-without-the-help-desk); [The Hacker News, 2021](https://thehackernews.com/2021/04/cost-of-account-unlocks-and-password.html)). `[UNVERIFIED original]`
- ME's own page says "one third" of help-desk calls are password resets; the claim is unsourced vendor copy ([ME](https://www.manageengine.com/products/ad-manager/delegate-ad-password-reset-and-account-unlock-permissions.html)).
- ME gives the task a dedicated Home tile ([me-01](top-admin-tasks-benchmark-evidence/me-01-home-dashboard.png)) and a Zia chat action ([help](https://www.manageengine.com/products/ad-manager/help/admin-settings/zia-configuration.html)).

**ME flow: Help Desk Reset Password Console** ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/active-directory-reset-password.html)). The shortest path uses "Generate password".

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Click the "Help Desk Reset Password Console" tile on Home; page load (14.5 s) | 1 | | 1 | demo |
| 2 | Type the name in the grid search | 1 | 1 | | demo |
| 3 | Enter; the grid filters in place | 1 | | | demo |
| 4 | "Reset Password" on the user's row; pop-up opens | 1 | | 1 | demo (me-03) |
| 5 | Choose "Generate password" ("Type a password" is preselected) | 1 | | | demo |
| 6 | Tick "User must change the password at next logon" (unticked by default) | 1 | | | demo |
| 7 | Clear "Account is locked out" to unlock | 1 | | | demo (control); its ticked state on a locked account is inferred |
| 8 | OK | 1 | | | demo |
| | **Total** | **8** | **1** | **2** | **T = 15.0 s** |

Notes on this path:
- With the preselected "Type a password", steps 5 becomes "type the password" and "type the confirmation", giving 9 I / 3 F / 2 S (20.1 s).
- Whether ME shows the generated password to the technician is `[UNVERIFIED]` (§6). We count the shorter path anyway.
- The alternative path, Management › Reset Password and then Unlock Users, takes two pages with a search on each. Its default password option is **"Same as logonname"** ([me-06](top-admin-tasks-benchmark-evidence/me-06-management-reset-password.png); [help](https://www.manageengine.com/products/ad-manager/help/user_management/general_attributes/reset_password_windows_users.html)). It is not itemised and not in the totals.

**Pain points**
- The console does not show whether the account is locked before you open the pop-up, because the lock column is off by default ([me-02](top-admin-tasks-benchmark-evidence/me-02-helpdesk-reset-console.png)).
- The grid mixes system and Exchange mailboxes in with people: 11 of 14 rows on the demo (me-02).
- Must-change is off by default (me-03). On the typed path, the technician knows a live password.
- There is no caller-verification step anywhere in ADMP. Help-desk-assisted verification needs ADSSP (ENH-09; ADSS W9).
- The console's help page does not mention unlock at all (help above).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` opens the search overlay | 1 | | 1 |
| 2 | Type "priya r". The results carry status chips: `Locked 09:12`, `Password expired` | 1 | 1 | |
| 3 | Enter. The user page opens with a banner: "Locked out 3× today. Last from LT-LON-0421" (P2) | 1 | | 1 |
| 4 | `R`, "Reset & unlock". The sheet opens with a generated passphrase that meets policy, "must change at next logon" **on**, and "unlock" **on** because the account is locked | 1 | | 1 |
| 5 | "Send code to •••• 4821" (ENH-09) | 1 | | |
| 6 | Type the code the caller reads back | 1 | 1 | |
| 7 | Enter to confirm | 1 | | |
| | **Total** (without verification, steps 5–6 drop: 5 / 1 / 3) | **7** | **2** | **3** |

The result shows the password with copy and a phonetic read-out. The audit line reads: "who, what, when, verified by OTP". Undo does not apply to a password reset.

**Target: ≤ 22 s with verification (model 17.0 s + 3 s wait budget = 20.0 s). ≤ 17 s without (12.5 s + 3 s = 15.5 s). No page load.**
- **Justification.** Verification adds 2 interactions on purpose, and it makes us 2 s slower than ME's shortest unsafe path in the model. Service-desk social engineering is a documented initial vector ([CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a); LAND §4.2).
- We still remove the 14.5 s console load. Lock status is visible in the search results.
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

**ME flow: across two products and two licences.**
- Half 1 is the ADAudit Plus Account Lockout Analyzer, Professional ([how-to](https://www.manageengine.com/products/active-directory-audit/how-to/find-out-what-is-locking-ad-account.html)). Its path is "Active Directory > User Management > Account Lockout Analyzer".
- Half 2 is ADManager Plus Unlock Users ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html)), because ADAudit Plus documents no unlock action.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | ADAP: "Active Directory" tab | 1 | | 1 | doc |
| 2 | "User Management" in the left pane | 1 | | | doc |
| 3 | "Account Lockout Analyzer". It lists locked accounts "sorted by time"; we assume the caller is near the top, so no search is counted | 1 | | 1 | doc |
| 4 | "Details" under "Analyzer Details". A modal opens with checks of services, scheduled tasks, drive maps, sessions and processes | 1 | | 1 | doc |
| 5 | Switch to the ADMP console (not counted, §1.2) | 0 | | | — |
| 6 | ADMP: Management tab | 1 | | 1 | doc |
| 7 | "Unlock Users" | 1 | | 1 | doc |
| 8 | Type the name (domain preselected) | 1 | 1 | | doc |
| 9 | Search | 1 | | | doc |
| 10 | Tick the user | 1 | | | inferred |
| 11 | Apply | 1 | | | doc |
| | **Total** | **10** | **1** | **5** | **T = 21.7 s** |

**Pain points**
- Two consoles: "For reports, we have to go back to ADAudit, which is not ideal." ([PeerSpot, Jai S, 2023-07-18](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))
- The analyzer is Professional-only ([pricing](https://www.manageengine.com/products/active-directory-audit/pricing-details.html)).
- OWA and ActiveSync sources need IIS logging ([help](https://www.manageengine.com/products/active-directory-audit/help/usecase/account-lockout-analyzer-overview.html)).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the name | 1 | 1 | |
| 3 | Enter. The user page opens with the lockout panel expanded. Each recent lockout shows the **caller computer** from DC event 4740 ([MS Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740)), the DC, the time and the failure count | 1 | | 1 |
| 4 | "Show failed sign-ins" expands the per-source breakdown in place | 1 | | |
| 5 | `U`, Unlock. A toast shows the audit line | 1 | | |
| | **Total** | **5** | **1** | **2** |

The next best action is offered as a link rather than another flow: "Notify user / open task on LT-LON-0421".

**Target: ≤ 15 s (model 11.1 s + 2 s wait budget = 13.1 s).**
- **Justification.** Diagnosis and the fix live on one page, in one product. This is the lockout root-cause half of the help-desk lead's win (`product-strategy.md` §3.2).
- **Dependency.** The source host needs DC security-event collection (DC agent or event forwarding, Phase 2). A process-level cause on the endpoint, which ME's Details modal shows, needs endpoint data (ENH catalog, lockout root cause). Until then our panel is shallower than ME's on that point.
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

**ME flow: header search, then AD Explorer** ([search help](https://www.manageengine.com/products/ad-manager/help/user_management/searching_active_directory_users_groups_computers.html); [AD Explorer help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html)). Confidence is low: whether the Properties tab shows lock, expiry and last logon together is `[UNVERIFIED]`.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Type the name in the header "Search AD Objects" box | 1 | 1 | | demo |
| 2 | Enter. A search **report** opens (≈6 s), with name columns only | 1 | | 1 | demo (me-04) |
| 3 | "AD Explorer" (top right) | 1 | | 1 | doc |
| 4 | Expand the domain and two OU levels to the user's OU (+1 per extra level) | 3 | | | inferred |
| 5 | Click the user. Its tabs open in a panel on the same page; Properties is the default | 1 | | | doc |
| 6 | "Entitlements" tab for group memberships | 1 | | | doc |
| | **Total** | **8** | **1** | **2** | **T = 15.0 s** |

Search results can show status only after adding columns, which only the built-in admin can set globally (search help).

**Pain points**
- The search result has names only, so status needs a second tool (me-04).
- Entitlements needs Professional plus the GRC add-on ([FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html)).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type a name, sAMAccountName, UPN, e-mail or employee ID. Each result row shows status chips: enabled or disabled, locked, password expired or expiring in N days, account expires, last sign-in. **For "is it locked, disabled or expired?", the answer is already on screen here** | 1 | 1 | |
| 3 | Enter for the full page: groups (direct and effective), devices, licences and recent changes | 1 | | 1 |
| | **Total** | **3** | **1** | **2** |

**Target: ≤ 12 s (model 8.5 s + 2 s wait budget = 10.5 s).**
- **Justification.** One search understands every identifier admins quote, and status is in the result row.
- **States to design:**
  - **stale data.** `lastLogonTimestamp` is updated only when it is older than the sync interval, which is 14 days by default, minus a random offset ([MS Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp)). So it only lags: the true last sign-in is between the stored value and up to 14 days later, never before. The chip says "Last sign-in 3 Oct, or up to 14 days later". The precise value is fetched from all DCs on demand;
  - ambiguous matches: two "Priya Raman"s show their department and OU to tell them apart;
  - out-of-scope objects are shown greyed with the reason (P8);
  - deleted objects carry a "Deleted" chip (T15).

### T04 · Retrieve a BitLocker recovery key (HD)

**Frequency (C).**
- Usually occasional, with extreme spikes. The 19 July 2024 CrowdStrike incident hit about 8.5 million Windows devices ([TechTarget](https://www.techtarget.com/cybersecurity/news/366596532/Microsoft-Faulty-CrowdStrike-update-affected-85M-devices)).
- Recovering those devices could require recovery keys ([CrowdStrike AD guide](https://crowdstrike.com/wp-content/uploads/2024/07/BitLocker-recovery-in-Microsoft-environments-using-Active-Directory-and-GPOs.pdf)).

**ME flow: BitLocker Recovery Keys report** ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-computer-reports.html); [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/unlock-and-recover-bitlocker-encrypted-drives.html)).

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Reports tab | 1 | | 1 | doc |
| 2 | "Computer Reports" menu | 1 | | | doc |
| 3 | "BitLocker Recovery Keys" | 1 | | 1 | doc |
| 4 | Domain checkbox: pre-ticked | 0 | | | demo (me-10) |
| 5 | Generate. This runs a domain-wide report | 1 | | | doc |
| 6 | Open the grid search | 1 | | | inferred |
| 7 | Type the computer name | 1 | 1 | | inferred |
| 8 | Enter | 1 | | | inferred |
| | **Total** | **7** | **1** | **2** | **T = 13.7 s** |

**Pain points**
- The flow is a domain-wide report, not a lookup. The KB's steps stop at "Generate" and "Download File"; finding one computer is not documented.
- There is no lookup by the **recovery key ID**, which is the identifier the user can actually read off the pre-boot screen ([MS Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-process)).
- No reveal step or audit of who viewed a key is documented.
- Build 8030 added a "dedicated interface" with no help page ([RN](https://www.manageengine.com/products/ad-manager/release-notes.html)). Its flow is `[UNVERIFIED]`.

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the **computer name or the first 8 characters of the key ID** | 1 | 1 | |
| 3 | Enter. The computer page opens | 1 | | 1 |
| 4 | "Show recovery key". An inline reason chooser expands; it is not a dialog | 1 | | |
| 5 | Pick a reason preset, for example "Caller on phone" | 1 | | |
| 6 | Step-up MFA prompt (TM §7.4, TM-D16): type the 6-digit code, which submits itself. Skipped inside the tenant's step-up window | 1 | 1 | 1 |
| | **Total** (inside the step-up window: 5 / 1 / 2) | **6** | **2** | **3** |

The key appears in 6-digit groups with copy. The reveal is audited and rate-limited per technician (TM §7.4).

**Target: ≤ 21 s (model 15.7 s + 3 s wait budget = 18.7 s). Inside the step-up window: ≤ 15 s (11.1 s + 2 s = 13.1 s).**
- **Justification.** We are 2 s slower than ME in the model, on purpose. A recovery key unlocks a whole disk, so the reason and the step-up are required by our threat model (TM §7.4).
- We win back time outside the model:
  - the key-ID lookup removes the "what is your computer called?" exchange;
  - there is no domain-wide report to generate.
- **States to design:**
  - several keys for one computer (one per volume, and older protectors), with the newest first and dated;
  - no key escrowed, which says so plainly and links to the escrow policy;
  - the key stored in Entra only (hybrid devices) is shown from Graph with its source labelled;
  - **incident mode**: a bulk lookup that pastes 200 key IDs and exports a list, with one step-up for the batch. This is the CrowdStrike case, and it pairs with P4.

### T05 · Retrieve a LAPS password (HD, AD)

**Frequency (C; E for volume).**
- ADMP ships a "LAPS Role" for technicians ([RN 8020](https://www.manageengine.com/products/ad-manager/release-notes.html)).
- ADAudit Plus audits LAPS reads ([help](https://www.manageengine.com/products/active-directory-audit/help/usecase/laps-auditing-reporting-capabilities.html)).
- Weekly volume is `[UNVERIFIED]`.

**ME flow: Windows LAPS through AD Explorer** ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/export-laps-password-reports.html)). The KB's steps are "AD Explorer" (top right), "Browse to computer location", then the "LAPS Details" section on the Properties tab.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | "AD Explorer" | 1 | | 1 | doc |
| 2 | Expand the domain and two OU levels (+1 per extra level) | 3 | | | inferred |
| 3 | Click the computer. "LAPS Details" shows on the Properties tab, which opens by default in a panel on the same page | 1 | | | doc |
| | **Total** | **5** | **0** | **1** | **T = 7.8 s** |

Legacy LAPS goes through a report instead: Workstation Computers, Generate, "Add or Remove Column", then move "Local Administrator Password(LAPS)" (same KB). It is not itemised and not in the totals.

**Pain points**
- There are two different paths for legacy and Windows LAPS.
- Viewing is audited only in ADAudit Plus, a separate product.
- ME's KB still names a setting that its release notes say was removed ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/fix-laps-password-not-visible.html)).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the computer name | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | "Show local admin password". The inline reason chooser expands | 1 | | |
| 5 | Pick a reason | 1 | | |
| 6 | Step-up MFA code (TM-D16). Skipped inside the step-up window | 1 | 1 | 1 |
| | **Total** (inside the step-up window: 5 / 1 / 2) | **6** | **2** | **3** |

Copy is offered, with an optional "rotate after use" toggle. Windows LAPS supports post-authentication rotation ([MS Learn](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)).

**Target: ≤ 21 s (model 15.7 s + 3 s wait budget = 18.7 s). Inside the step-up window: ≤ 15 s (13.1 s). This is a loss against ME's 7.8 s, and we accept it.**
- **Justification.** A LAPS password is local-admin access. The threat model requires the reveal to be audited in the product that showed it, with step-up and per-technician rate limits (TM §7.4, threat TM-X4).
- ME's tree browse costs one more click per OU level, and it has no reason, step-up or same-product audit.
- **States to design:**
  - legacy and Windows LAPS on the same estate, shown with one label;
  - password expired or rotation pending;
  - an encrypted Windows LAPS password the technician cannot decrypt, which explains who can (P8).

### T06 · Add a user to a group (HD, AD)

The job is to add one user to one group. Removal is the same flow on ME ("Remove from group") and on ours (Groups tab, select, Delete, Confirm).

**Frequency (B, C).**
- PCI DSS 7.2.3 requires approved privilege changes ([MS Learn PCI 7](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-7)).
- Group membership is an action in the ME mobile app ([help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-management/ad-management.html)).

**ME flow: Bulk User Modification › Group Attributes** ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html); [me-12](top-admin-tasks-benchmark-evidence/me-12-group-attributes.png)).

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | demo |
| 2 | "Group Attributes" | 1 | | 1 | demo (me-12) |
| 3 | Object picker beside "Add to group": "+", type, Search, select, OK (§1.2) | 5 | 1 | 1 | demo ("+" pop-up); inside inferred |
| 4 | Type the user ("Enter name(s) to search" is preselected) | 1 | 1 | | demo |
| 5 | Search | 1 | | | demo |
| 6 | Tick the user | 1 | | | doc |
| 7 | Apply | 1 | | | doc |
| | **Total** | **11** | **2** | **3** | **T = 22.2 s** |

The Modify Single User path is longer: it has an Action drop-down and a template pop-up before any edit ([help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-single-user.html)). Group-side management is Professional-only ([pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html)).

**Pain points**
- The job is filed under "Bulk User Modification", even for one user.
- No preview of nesting effects or privileged groups is documented.

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the user | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | `G`, "Add to group". A sheet opens | 1 | | 1 |
| 5 | Type the group name in the type-ahead | 1 | 1 | |
| 6 | Enter to pick. The preview reads: "+1 group: SG-Finance-Readers (members 3,114)" (P3) | 1 | | |
| 7 | Confirm. A toast with Undo appears (P5) | 1 | | |
| | **Total** | **7** | **2** | **3** |

The same sheet works from the group side, and for many users (T11).

**Target: ≤ 22 s (model 17.0 s + 3 s wait budget = 20.0 s).**
- **Justification.** The action lives where the object is. No template pop-up stands between the technician and the edit.
- **States to design:**
  - **protected or privileged group** (Domain Admins, Enterprise Admins, Schema Admins, AdminSDHolder-protected and custom Tier-0 groups). This needs typed confirmation plus an approver per policy, and the impact line reads "grants Tier-0" (P6);
  - nested-group effect: "also grants 4 groups via nesting";
  - already a member;
  - cross-domain group;
  - out-of-scope group (P8).

### T07 · Create one joiner with manager, mailbox, licence and groups (AD)

**Frequency (A).**
- About 33 hires per 1,000 employees per month ([BLS JOLTS](https://www.bls.gov/news.release/archives/jolts_03132026.htm)).
- ME puts "Account Provisioning (via Templates)" in the Home quick links (me-01).

**ME flow: Create Single User with a prepared template** ([help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html); [templates](https://www.manageengine.com/products/ad-manager/help/user_management/creating_user_templates.html)). The template supplies the container, groups, mailbox and licence `[inferred]`.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | demo |
| 2 | "Create Single User". A full reload, 16.1 s | 1 | | 1 | demo (me-07) |
| 3 | "Select Template" drop-down (defaults to "System Template") → the prepared template | 2 | | | demo |
| 4 | First name | 1 | 1 | | demo |
| 5 | Last name. Naming formats fill Logon Name, pre-Windows 2000 name and Full name | 1 | 1 | | demo (fields); auto-fill inferred |
| 6 | "Contact" tab | 1 | | | demo (me-11) |
| 7 | Manager: object picker ("+", type, Search, select, OK) | 5 | 1 | 1 | demo ("+", me-11); inside inferred |
| 8 | Create | 1 | | | demo (me-11) |
| | **Total** | **13** | **3** | **3** | **T = 26.7 s** |

With the default System Template, the admin also has to:
- type the three mandatory names: Logon Name, pre-Windows 2000 name and Full name (me-07; the help says "The mandatory parameters for creating a user are the Logon Name, SAMaccount Name and the FullName");
- pick the container ("Select Container" defaults to `CN=Users`);
- set the groups;
- set Country, because "The country attribute is mandatory to apply O365 license" (help).

That path is not itemised and not in the totals. One-time setup for the template path is the template itself, the naming formats and tenant onboarding.

**Pain points**
- The page weighs 10.4 MB (ADM §4.2).
- "Changing domain in middle of things will reset all domain specific attributes" (help).
- Mailbox follow-ups are deferred to a "Delayed Management Tasks" queue (help).
- Naming formats are macro strings such as `%givenName%1[L]()%sn%2[L]()` (ADM §4.1).
- The manager is on a different tab from the name, behind a picker pop-up (me-11).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `N`, "New user". A sheet opens with the last-used role template preselected, for example "Sales · London" | 1 | | 1 |
| 2 | First name | 1 | 1 | |
| 3 | Last name | 1 | 1 | |
| 4 | Type the manager in the type-ahead | 1 | 1 | |
| 5 | Enter to pick | 1 | | |
| 6 | Create | 1 | | |
| | **Total** | **6** | **3** | **1** |

As the admin types, a live preview panel shows every derived value:
- UPN, sAMAccountName, display name and e-mail, **each checked for duplicates**;
- the OU;
- the 3 groups;
- the licence, and a usageLocation derived from the office.

Each derived value is editable in place. The result page shows AD, mailbox and licence each with their own status. Mailbox provisioning shows "pending (Exchange Online), usually < 5 min" instead of a silent queue.

**Target: ≤ 18 s (model 14.9 s + 1 s wait budget = 15.9 s).**
- **Justification:**
  - no 16 s page load;
  - the manager is on the same form as the name;
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

**ME flow: Create Bulk Users** ([help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_multiple_windows_users.html); [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/set-ad-user-accounts-to-expire.html); [CSV format](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-user-creation-csv.html)). The page is a 3-step wizard ([me-08](top-admin-tasks-benchmark-evidence/me-08-create-bulk-users.png)).

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | demo |
| 2 | "Create Bulk Users". A full reload, 22.6 s | 1 | | 1 | demo (me-08) |
| 3 | "Select Template" drop-down → prepared template (domain and M365 account preselected) | 2 | | | demo |
| 4 | "Import". A modal opens | 1 | | 1 | demo (button); doc (modal) |
| 5 | OS file picker: open, choose the file | 2 | | 1 | doc |
| 6 | Import | 1 | | | doc |
| 7 | Review the editable grid; Next → "Choose Container" | 1 | | | demo (wizard step) |
| 8 | Choose the container: expand the domain, select the OU | 2 | | | demo (step name); tree inferred |
| 9 | Create. The "Creation and Status" step shows the result | 1 | | | demo (step name); doc |
| | **Total** | **12** | **0** | **4** | **T = 21.0 s, plus CSV rework** |

**CSV rules the admin must meet** (CSV format page, verbatim where quoted):
- headers must be "attribute names as defined in the Active Directory";
- `OUName`: "OU name should be specified in the distinguished name (DN) format. Also, ensure that you enclose the DN within double quotes.";
- `memberOf` may be "the distinguished name (DN) or sAMAccount name or display name (displayNAme) or email address (mail) of the group enclosed within double quotes". `manager` accepts the same four forms;
- country: "The three values c, co, countryCode are mandatory";
- the help's own sample uses `managedby` for the manager, which conflicts with the format page's `manager`.

**Pain points**
- **ME's own guidance disagrees.** The in-product hint says "Specify memberOf, manager in DN format or Sam Account Name and ouName in DN format enclosed by double quotes." (me-08). The format page also accepts display name and e-mail. An admin with an HR export of manager e-mails cannot tell from the screen whether it will import.
- An HR export still cannot be imported as-is. It fails on the LDAP-name headers, the quoted `OUName` DN and the `c`/`co`/`countryCode` triple.
- ME's KB warns that CSV runs can end in "error messages, partial updates, or no changes being applied" ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/csv-bulk-modification-failure-reasons.html)).
- Per-row failure reasons and retrying only the failed rows are **not documented** `[UNVERIFIED]`.
- "Validate CSV" exists only for modify-via-template ([help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-users-using-template.html)).

**activeDIQ flow.** One page in three states: Map, Validate, Run.

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `N`. The New user sheet opens | 1 | | 1 |
| 2 | "Import from a file". The import page opens | 1 | | 1 |
| 3 | OS file picker: open, choose. Dropping the file instead is 1 I and no screen | 2 | | 1 |
| 4 | **Map.** Columns map automatically from friendly headers ("First name", "Surname", "Manager email", "Dept"). Unmapped columns are flagged. Confirm the mapping | 1 | | |
| 5 | **Validate** runs by itself, as a dry run before any write: duplicates within the file and against the directory, the manager and groups resolve, the OU exists or comes from the role rule, password policy, licence seats. Result: "**196 ready · 4 need attention**". Each problem row is fixable inline or can be excluded | 0 | | |
| 6 | **Run.** "Create 196". Progress runs in the background. The admin can leave the page, and a notification fires when it is done | 1 | | |
| | **Total** (before row fixes) | **6** | **0** | **3** |

The result reads: "**187 of 200 created. 13 failed. Here is why**", with the failures grouped by reason (for example "8 × manager not found", "5 × UPN suffix not allowed"). From the result the admin can use **Retry failed after fixing**, **Export failures**, and **Undo this batch** for objects created by it (P5).

**Target: ≤ 17 s of interaction (model 11.9 s + 3 s wait budget = 14.9 s), before row fixes. Validating 200 rows ≤ 10 s. Creating 200 users ≤ 120 s on the reference lab (T-0012), running in the background.**
- **Justification:**
  - the admin's time goes into data, not syntax;
  - we accept the file HR already produces;
  - the partial-failure state is designed, not an afterthought.
- **The runtime targets are starting budgets** for the directory-engineer to confirm, not measured numbers.
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

**ME flow per leaver: disable with a Disable Policy, then convert the mailbox** ([bulk mod help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html); [mailbox help](https://www.manageengine.com/products/ad-manager/help/office365/mailbox-management/mailbox-management.html)).

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | doc |
| 2 | "Enable/Disable Users" (Bulk User Modification) | 1 | | 1 | doc |
| 3 | Enable/Disable drop-down → Disable | 2 | | | doc |
| 4 | Type the name | 1 | 1 | | doc |
| 5 | Search | 1 | | | doc |
| 6 | Tick the user | 1 | | | inferred |
| 7 | Apply. The Disable Policy then removes groups, moves the OU and revokes the licence | 1 | | | doc (Apply); that the policy runs here is inferred |
| 8 | Microsoft 365 tab (≈26 s, ADM §4.2) | 1 | | 1 | doc |
| 9 | "Mailbox Management" option | 1 | | | doc |
| 10 | "Mailbox Conversion" | 1 | | 1 | doc |
| 11 | Type the name (single tenant preselected) | 1 | 1 | | doc |
| 12 | Search | 1 | | | inferred |
| 13 | Select the mailbox | 1 | | | doc |
| 14 | Action drop-down → Shared Mailbox | 2 | | | doc |
| 15 | Apply | 1 | | | doc |
| | **Total** | **17** | **2** | **4** | **T = 31.3 s** |

**One-time setup, not in the totals** ([policy help](https://www.manageengine.com/products/ad-manager/help/admin-settings/windows-active-directory-delete-policy.html)). It takes **12 I / 0 F / 3 S**:
- Admin tab (1, S);
- "Delete/Disable Policy" (1, S);
- "Disable Policy" tab (1);
- "Hide from Exchange address lists" (1);
- remove from all groups (1);
- move to a specific OU (1), then the OU picker (4, S);
- revoke the Office 365 licence (1);
- Save (1).

**Pain points**
- **No preview** of what the policy will change (ADM §4.3). The policy page documents none.
- On-premises, the policy *disables* the mailbox rather than converting it (policy help).
- Mailbox conversion is a separate task in a separate tab.
- Automating this needs Professional orchestration ([help](https://www.manageengine.com/products/ad-manager/help/orchestration/new-orchestration-template.html)).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the name | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | `O`, "Offboard". The **leaver plan** opens from policy, with every line listed and toggleable: disable; reset to a random password; remove 14 groups, each named; move to `OU=Leavers`; revoke 2 licences; convert the mailbox to shared and grant the manager access; hide from the GAL; revoke sessions. A "When" control offers "now" or "end of day 31 Oct" | 1 | | 1 |
| 5 | Confirm | 1 | | |
| | **Total** | **5** | **1** | **3** |

**Target: ≤ 17 s (model 12.5 s + 3 s wait budget = 15.5 s).**
- **Justification.** One plan across AD, Exchange and M365, previewed before it runs (ENH-04). Disable, groups, OU and licence are undoable for a set period (P5).
- **States to design:**
  - the leaver is in privileged groups: typed confirmation, and the plan flags "removes Tier-0 access" (P6);
  - the leaver manages 6 direct reports: prompt to reassign;
  - the mailbox is on litigation hold;
  - scheduled offboarding is visible on the user page as a countdown;
  - partial failure: AD done but licence revoke failed, with retry.

### T10 · Process a mover: title, department, manager, groups, OU (AD, HD)

The job: new title, department and manager; remove one old-team group and add one new-team group; move to the new department's OU.

**Frequency (E; B).**
- No public internal-mobility rate was found `[UNVERIFIED]`.
- PCI DSS 8.2.4 requires approved changes to user IDs ([MS Learn PCI 8](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-8)).

**ME flow: Modify Single User, then a separate Move Users task** ([modify help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-single-user.html); [bulk mod help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-bulk-users-modification.html)).
- The help documents the steps up to the template pop-up, plus Preview and Update User.
- It does not say how the manager and groups are changed. Those steps reuse the create form's controls (me-11) and are `[inferred]`.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | doc |
| 2 | "Modify Single User" | 1 | | 1 | doc |
| 3 | Type the name (domain preselected) | 1 | 1 | | doc |
| 4 | Search | 1 | | | doc |
| 5 | "Action" drop-down → Modify User | 2 | | | doc |
| 6 | "Select Template" pop-up (System Template is the default): OK | 1 | | 1 | doc |
| 7 | The modify form opens | 0 | | 1 | inferred |
| 8 | "Contact" tab | 1 | | | inferred from me-11 |
| 9 | Type the new title | 1 | 1 | | inferred from me-11 |
| 10 | Department drop-down | 2 | | | inferred from me-11 |
| 11 | Manager: object picker | 5 | 1 | 1 | inferred from me-11 |
| 12 | "Member Of" tab | 1 | | | inferred |
| 13 | Select the old group, then Remove | 2 | | | inferred |
| 14 | Add the new group: object picker | 5 | 1 | 1 | inferred |
| 15 | Preview | 1 | | 1 | doc |
| 16 | Update User | 1 | | | doc |
| 17 | Management tab | 1 | | 1 | doc |
| 18 | "Move Users" | 1 | | 1 | doc |
| 19 | Container: OU picker ("+") | 4 | | 1 | doc ("+" icon); picker inferred |
| 20 | Type the name | 1 | 1 | | doc |
| 21 | Search | 1 | | | doc |
| 22 | Tick the user | 1 | | | inferred |
| 23 | Apply | 1 | | | doc |
| | **Total** | **36** | **5** | **10** | **T = 69.8 s** |

Copying groups from a colleague through "Copy User Attributes" is `[UNVERIFIED]` for `memberOf`. Whether it appends or replaces is not documented ([help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-copy-user.html)).

**Pain points**
- Two tasks for one job.
- Copy-access behaviour is undocumented.

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the name | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | `M`, "Change role". A sheet opens | 1 | | 1 |
| 5 | Title | 1 | 1 | |
| 6 | Department | 1 | 1 | |
| 7 | Manager (type-ahead) | 1 | 1 | |
| 8 | Enter to pick | 1 | | |
| 9 | "Match access to": type a colleague | 1 | 1 | |
| 10 | Enter. The **diff** appears: "+1 group / −1 group", each named and individually untickable, and "OU: Sales → Finance (rule: department)" | 1 | | |
| 11 | Confirm | 1 | | |
| | **Total** | **11** | **5** | **3** |

The diff states clearly that matching access **replaces**, it does not append, and it lists what is removed.

**Target: ≤ 34 s (model 27.9 s + 3 s wait budget = 30.9 s).**
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

**ME flow: Group Attributes with CSV import** (bulk mod help; [me-12](top-admin-tasks-benchmark-evidence/me-12-group-attributes.png)). The admin also has to prepare the CSV, which is not counted.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | demo |
| 2 | "Group Attributes" | 1 | | 1 | demo (me-12) |
| 3 | Object picker beside "Add to group" | 5 | 1 | 1 | demo ("+"); inside inferred |
| 4 | "CSV Import" radio | 1 | | | demo (me-12) |
| 5 | OS file picker: open, choose the CSV | 2 | | 1 | inferred |
| 6 | Match-attribute drop-down | 2 | | | inferred |
| 7 | Search | 1 | | | demo (button) |
| 8 | Select all | 1 | | | inferred |
| 9 | Apply | 1 | | | doc |
| | **Total** | **15** | **1** | **4** | **T = 26.8 s** |

Group management is Professional-only ([pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html)). Whether this user-side path works in Standard is `[UNVERIFIED]`.

**Pain points**
- The list has to become a CSV file first.
- Unmatched or ambiguous rows are not shown before Apply `[UNVERIFIED]`.

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the group | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | "Add members". A sheet opens | 1 | | 1 |
| 5 | **Paste** 50 lines of mixed sAMAccountNames, e-mails and display names. Resolution: "48 matched · 2 ambiguous · 0 not found" | 1 | | |
| 6 | Pick the right match for the first ambiguous entry | 1 | | |
| 7 | Pick the right match for the second | 1 | | |
| 8 | Confirm. The preview reads "+48, 2 already members" | 1 | | |
| | **Total** | **8** | **1** | **3** |

**Target: ≤ 22 s (model 16.4 s + 3 s wait budget = 19.4 s).**
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

**ME flow: Organization Attributes** (bulk mod help). This assumes the 300 users are exactly one OU; any other selection needs the CSV path.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | doc |
| 2 | "Organization Attributes" | 1 | | 1 | doc |
| 3 | Tick the attribute, for example Company | 1 | | | doc |
| 4 | Type the value | 1 | 1 | | doc |
| 5 | "Add OUs": OU picker | 4 | | 1 | demo (link, me-12); picker inferred |
| 6 | Search with the box blank ("Leave this field blank to see all") | 1 | | | demo (hint, me-12) |
| 7 | Select all | 1 | | | inferred |
| 8 | Apply | 1 | | | doc |
| | **Total** | **11** | **1** | **3** | **T = 20.2 s** |

Gaps and risks:
- Whether select-all spans grid pages for 300 users is `[UNVERIFIED]`.
- On the CSV path, ticking "clear attribute value … if empty" **wipes** values wherever a cell is blank (CSV modify help).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | Users | 1 | | 1 |
| 2 | Type a filter, for example "department: Retail Ops" | 1 | 1 | |
| 3 | Enter. The list filters in place | 1 | | |
| 4 | Ctrl+A. The banner reads "**All 300 matching selected**, not just the 50 on screen" | 1 | | |
| 5 | "Edit attribute". A sheet opens | 1 | | 1 |
| 6 | Type the attribute, for example "Company" | 1 | 1 | |
| 7 | Enter to pick | 1 | | |
| 8 | Type the value | 1 | 1 | |
| 9 | Confirm the preview: "300 changes · 12 already have this value · 0 blanks will be written" | 1 | | |
| | **Total** | **9** | **3** | **2** |

Undo is available for the batch (P5).

**Target: ≤ 25 s (model 20.1 s + 2 s wait budget = 22.1 s). Parity on modelled time.**
- **Justification.** The win is not speed. It is a selection by any attribute rather than by OU, a selection that cannot be misread, plus preview and undo.
- **States to design:**
  - selection across 12,000 rows;
  - mixed current values, with a histogram in the preview;
  - an attribute the technician may not write (P8);
  - a value that fails schema syntax, caught before the write.

### T13 · Set or extend a contractor's account expiry (HD, AD)

**Frequency (B, C).**
- NIST SP 800-53 AC-2(2): disable temporary accounts automatically after a defined period ([STIG Viewer](https://www.stigviewer.com/controls/nist-800-53/AC-2(2))).
- "Set account expiry" is an ME mobile action ([help](https://www.manageengine.com/products/ad-manager/help/mobile/ad-management/ad-management.html)).

**ME flow, single user: Modify Single User › Account tab** ([modify help](https://www.manageengine.com/products/ad-manager/help/user_management/active-directory-modify-single-user.html); [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/set-ad-user-accounts-to-expire.html)). The KB documents the "Account" tab and "End of" on the create form and templates. On the modify form they are `[inferred]`.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | doc |
| 2 | "Modify Single User" | 1 | | 1 | doc |
| 3 | Type the name | 1 | 1 | | doc |
| 4 | Search | 1 | | | doc |
| 5 | Action → Modify User | 2 | | | doc |
| 6 | Template pop-up: OK | 1 | | 1 | doc |
| 7 | The modify form opens | 0 | | 1 | inferred |
| 8 | "Account" tab | 1 | | | doc (KB) |
| 9 | "End of" | 1 | | | doc (KB) |
| 10 | Date pop-up: open, next month, pick the day | 3 | | 1 | inferred |
| 11 | Update User | 1 | | | doc |
| | **Total** | **13** | **1** | **5** | **T = 25.6 s** |

For 20 users, ME's Enable/Disable Users page carries an "Account Expires" option (bulk mod help). That path is not itemised and not in the totals.

**Pain points**
- Expiry lives on a page labelled Enable/Disable.
- On the CSV path, an empty `accountExpires` with the "clear" option ticked is set to "24 hours from the time of modification" ([help](https://www.manageengine.com/products/ad-manager/help/csv-import-management/active-directory-users-modification-csv.html)).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the name | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | Click the "Account expires" field on the user page | 1 | | |
| 5 | Type "+90d" or "31 Mar". The resolved instant and its time zone are shown next to the input | 1 | 1 | |
| 6 | Enter. A toast with Undo appears | 1 | | |
| | **Total** | **6** | **2** | **2** |

For 20 contractors the flow is 5 I / 0 F / 2 S:
1. Open the saved view "Contractors expiring in 30 days" (1, S).
2. Ctrl+A (1).
3. "Extend expiry", which opens a sheet (1, S).
4. "+90 days" (1).
5. Confirm (1).

**Target: ≤ 18 s (model 14.3 s + 2 s wait budget = 16.3 s).**
- **Justification.** The attribute is edited inline where it is displayed, and relative dates accept what admins actually say.
- **States to design:**
  - the date is in the past, so the field warns that the account will be disabled now;
  - the account has already expired and is disabled;
  - **time zone.** `accountExpires` is an absolute instant: a FILETIME in UTC ([MS Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires)). ADUC's "End of <date>" writes the start of the following day in the local time zone of the admin's machine `[confirm with ad-expert]`. So we show and write the expiry as an exact instant in a stated time zone. The default is the user's office time zone, and the field shows it, for example "Access ends 1 Apr 2027 00:00 Europe/London (31 Mar 23:00 UTC)". The field also says how ADUC will display the date.

### T14 · Assign an M365 licence (AD)

**Frequency (C; E).**
- The job tracks joiners and leavers (T07, T09) by inference.
- ME offers add, replace and remove, by group or CSV ([help](https://www.manageengine.com/products/ad-manager/help/office365/management/license-management.html)).

**ME flow: Microsoft 365 tab › Assign/Remove Licenses** (licence help). The M365 tab took ≈26 s to render (ADM §4.2).

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Microsoft 365 tab | 1 | | 1 | doc |
| 2 | "Assign/Remove Licenses" under Management | 1 | | 1 | doc |
| 3 | "Configure Licenses" on the tenant. A pop-up opens | 1 | | 1 | doc |
| 4 | Tick the licence | 1 | | | inferred |
| 5 | OK | 1 | | | inferred |
| 6 | Choose add, replace or remove | 1 | | | doc |
| 7 | "User Location" drop-down | 2 | | | doc |
| 8 | Type the user | 1 | 1 | | doc |
| 9 | Enter | 1 | | | inferred |
| 10 | Tick the user | 1 | | | doc |
| 11 | Apply | 1 | | | doc |
| | **Total** | **12** | **1** | **3** | **T = 21.6 s** |

**Pain points**
- A separate iframe app with its own navigation (ADM §4.1).
- The help still uses "Office 365" labels; the demo tab says "Microsoft 365".

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the user | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | "Assign" in the Licences section. A sheet opens | 1 | | 1 |
| 5 | Pick a SKU. The list shows free seats, for example "E3 · 12 of 250 free" | 1 | | |
| 6 | Confirm | 1 | | |
| | **Total** | **6** | **1** | **3** |

If `usageLocation` is missing, it is set inline in the same sheet, because Graph requires it before a licence can be assigned ([MS Learn](https://learn.microsoft.com/en-us/graph/api/user-assignlicense)).

**Target: ≤ 19 s (model 13.8 s + 3 s wait budget = 16.8 s).**
- **Justification.** AD and cloud live on one object page (ENH "one console").
- **States to design:**
  - no seats left;
  - the licence comes from a group (group-based licensing), shown as inherited and not removable here, with a link to the group;
  - service-plan toggles collapsed by default;
  - a Graph throttling retry with a visible status.

### T15 · Restore a user deleted by mistake (AD)

**Frequency (E).**
- Rare `[UNVERIFIED]`. It is included for its stakes (§1.1).
- ME has a KB article for it ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/how-to-restore-deleted-active-directory-users.html)).

**ME flow: Management › User Management › Restore Deleted Users, under Bulk User Modification** (KB). User Management is the Management tab's default landing ([me-05](top-admin-tasks-benchmark-evidence/me-05-management-user-landing.png)).

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Management tab | 1 | | 1 | doc |
| 2 | "Restore Deleted Users" | 1 | | 1 | doc |
| 3 | Domain: preselected | 0 | | | demo (me-12 pattern) |
| 4 | Type the name | 1 | 1 | | doc |
| 5 | Search | 1 | | | doc |
| 6 | Tick the user | 1 | | | doc |
| 7 | Apply | 1 | | | doc |
| | **Total** | **6** | **1** | **2** | **T = 12.4 s** |

**What comes back.**
- The KB says "The Recycle Bin feature should be enabled for the configured domain. Only then will all the user account attributes be restored."
- With the AD Recycle Bin on, objects are "restored in their entirety", and "all link-valued and non-link-valued attributes … are preserved" ([MS Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)). That includes group memberships.
- Fuller recovery needs the paid Backup add-on or RecoveryManager Plus ([FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html)).

**Pain points**
- A single restore is filed under "Bulk User Modification".
- No preview of what will come back is documented.

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type the name. Deleted objects show in the results with a chip: "Deleted 1 Oct 16:42 by svc-hr-sync" | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | "Restore". A sheet opens with the preview: "to `OU=Sales,…` · 12 group memberships and all attributes restored, including the password (Recycle Bin on)", plus a toggle "Require a new password at next sign-in" (our policy choice, off by default) | 1 | | 1 |
| 5 | Confirm | 1 | | |
| | **Total** | **5** | **1** | **3** |

The deletion also appears in "Recent changes" with an Undo (P5).

**Target: ≤ 17 s (model 12.5 s + 3 s wait budget = 15.5 s). Parity on modelled time.**
- **Justification.** The win is not speed:
  - the deleted object is found where people look, by search, not under "Bulk User Modification";
  - the preview says exactly what comes back before anything is written.
- **States to design:**
  - **Recycle Bin off** (tombstone reanimation): most attributes and all group memberships are lost, and the password does not survive. The preview lists what **cannot** be restored, sets a new password as a required step, and offers to re-apply memberships from activeDIQ's own change history;
  - the deletion looks malicious (deleted by an unexpected account): the preview suggests turning the new-password toggle on;
  - the original OU has since been deleted;
  - the name or UPN is now taken by someone else;
  - beyond the tombstone or deleted-object lifetime.

### T16 · Who removed X from Domain Admins, and when (SEC, AD)

**Frequency (B, C).**
- PCI DSS 10.4.1 requires daily review of security-event logs, and 10.2.1.5 requires logging privilege elevation ([MS Learn PCI 10](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-10)).
- ME sells alerting for privileged-group changes ([ADAP alerts](https://www.manageengine.com/products/active-directory-audit/active-directory-change-alerts.html)).
- The investigation itself is event-driven.

**ME flow: ADAudit Plus, a separate product** ([how-to](https://www.manageengine.com/products/active-directory-audit/how-to/how-to-track-changes-in-active-directory-groups.html); [report page](https://www.manageengine.com/products/active-directory-audit/active-directory-group-audit-report.html)). One-time DC audit-policy and event-log setup comes first ([audit policy](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-audit-policies-manually.html); [event log](https://www.manageengine.com/products/active-directory-audit/help/data-source/ad-audit-configure-event-log-settings.html)).

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Reports tab | 1 | | 1 | doc |
| 2 | "Group Management" in the left pane | 1 | | | doc |
| 3 | "Recently Removed Members from Security Groups". Its columns include removed member, caller user name, modified time, DC and caller machine name | 1 | | 1 | doc (report page) |
| 4 | Domain: preselected | 0 | | | inferred |
| 5 | Period drop-down | 2 | | | inferred |
| 6 | Generate | 1 | | | doc |
| 7 | Open the grid search | 1 | | | inferred |
| 8 | Type the member's name | 1 | 1 | | inferred |
| 9 | Enter | 1 | | | inferred |
| | **Total** | **9** | **1** | **2** | **T = 16.3 s** |

ADAudit Plus build 9000 renamed its tabs ([RN](https://www.manageengine.com/products/active-directory-audit/adaudit-plus-release-notes.html)), so the navigation labels are `[UNVERIFIED]`.

**ADManager Plus alone cannot answer this** for changes made outside it:
- AD Explorer's History lists "modifications made to the specified object using ADManager Plus" ([help](https://www.manageengine.com/products/ad-manager/help/introduction/exploring_active_directory_services.html));
- the technician audit report covers technicians' actions in ADMP ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-technician-audit-report.html)).

**Pain points**
- A second product and a second licence for a question about the group the admin is managing.
- The answer is a report to generate, not a history on the group.

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type "domain admins" | 1 | 1 | |
| 3 | Enter | 1 | | 1 |
| 4 | History tab (in-page) | 1 | | |
| 5 | Type the member's name in the filter. The row reads: "**Removed** Priya Raman · by `CORP\j.ops` from `ADM-WS-07` · 1 Oct 22:14 · via ADUC (DC event 4729)" | 1 | 1 | |
| | **Total** | **5** | **2** | **2** |

Event 4729 is "A member was removed from a security-enabled global group" ([MS Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)). From the row, the admin can **revert** (re-add, with the P6 confirmation).

**Target: ≤ 17 s (model 13.0 s + 2 s wait budget = 15.0 s).**
- **Justification.** One console answers it, from the group's own page.
- **Dependency, and the stale-data state.**
  - "Who" needs DC security-event collection (Phase 2), and ADAudit-parity reporting is a later milestone (D-0001).
  - Changes made through activeDIQ are always attributed.
  - Before event collection exists, the row shows **when, and on which DC**, from linked-value replication metadata ([MS Learn, msDS-ReplValueMetaData](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-replvaluemetadata)), and says "who: needs DC event collection".
  - The ad-expert should confirm the LVR detail in T-0009 review.
- **States to design:**
  - removed and re-added several times;
  - change made by a service account;
  - events past retention.

### T17 · Clean up stale computers: 90 days → disable → quarantine → delete (AD)

**Frequency (B).**
- Microsoft's guidance is not to treat devices active within 21 days as stale. Its example disables devices after 90 days and deletes them after 120 ([MS Learn](https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices)).
- In practice this runs monthly to quarterly (inference).

**ME flow: a one-off cleanup over two visits** ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/find-and-remove-inactive-ad-computers.html); [report help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-computer-reports.html)).
- The KB documents find-and-delete in one pass: "More Actions → Check All → Action → Delete Computers".
- The safer disable-and-quarantine path below uses the report toolbar we observed ([me-09](top-admin-tasks-benchmark-evidence/me-09-inactive-computers-report.png)).
- We assume the selection survives Disable, which favours ME.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| | *Visit 1: find, disable, quarantine* | | | | |
| 1 | Reports tab | 1 | | 1 | doc |
| 2 | "Computer Reports" | 1 | | | doc |
| 3 | "Inactive Computers". The period defaults to "Last 30 days", served from a cached run dated 6 days earlier | 1 | | 1 | doc; demo (me-09) |
| 4 | Domain: pre-ticked | 0 | | | demo (me-10 pattern) |
| 5 | Period drop-down → 90 days | 2 | | | doc |
| 6 | Generate | 1 | | | doc |
| 7 | "More Actions" → "Check All" | 2 | | | doc (KB) |
| 8 | "Disable" (toolbar). A confirmation opens | 1 | | 1 | demo (toolbar); confirmation inferred |
| 9 | Confirm | 1 | | | inferred |
| 10 | "Move" (toolbar). The OU picker opens | 1 | | 1 | demo (toolbar) |
| 11 | Expand, select the quarantine OU, OK | 3 | | | inferred |
| | *Visit 2, weeks later: delete from quarantine* | | | | |
| 12 | Reports tab | 1 | | 1 | doc |
| 13 | "Computer Reports" | 1 | | | doc |
| 14 | "Inactive Computers" (the default period is fine now) | 1 | | 1 | doc |
| 15 | "Add OUs": OU picker for the quarantine OU | 4 | | 1 | doc ("optionally choose an OU"); picker inferred |
| 16 | Generate | 1 | | | doc |
| 17 | "More Actions" → "Check All" | 2 | | | doc (KB) |
| 18 | "Delete" (toolbar). A confirmation opens | 1 | | 1 | demo (toolbar); doc (KB); confirmation inferred |
| 19 | Confirm | 1 | | | inferred |
| | **Total** (visit 1: 14 / 0 / 4; visit 2: 12 / 0 / 4) | **26** | **0** | **8** | **T = 44.6 s** |

Other notes on the ME flow:
- Whether "Check All" spans all result pages is `[UNVERIFIED]`; if it does not, ME's count grows with the result count.
- **ME's automated path** (Professional only) is a one-time setup of 12 documented steps (KB; [use case](https://www.manageengine.com/products/ad-manager/help/automation/usecase2-automation.html); [policy](https://www.manageengine.com/products/ad-manager/help/automation/configuring-automation-policy.html)). It is not in the totals.

**Pain points**
- No undo is documented.
- There is no named exclusion list, only conditions.
- Last Logon shows a raw `0` (me-09).
- The default period is 30 days, below Microsoft's own 90-day example.

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| | *Visit 1* | | | |
| 1 | "Clean up" | 1 | | 1 |
| 2 | "Stale computers" card, for example "1,284 inactive > 90 days · servers excluded". Each row shows `lastLogonTimestamp` **and** `pwdLastSet`, with the "or up to 14 days later" wording (T03) | 1 | | 1 |
| 3 | Ctrl+A (all matching) | 1 | | |
| 4 | "Quarantine". The plan sheet reads: "disable now → move to `OU=Quarantine` → delete after 30 days, with a digest 3 days before" | 1 | | 1 |
| 5 | Turn on "Repeat monthly" | 1 | | |
| 6 | Type the count, the deliberate confirmation for more than 100 objects (P6) | 1 | 1 | |
| 7 | Confirm | 1 | | |
| | *Visit 2, after the digest* | | | |
| 8 | "Clean up" | 1 | | 1 |
| 9 | "Pending deletion: 1,284 · Review & approve". A sheet opens with the list and any computers that became active and were auto-restored | 1 | | 1 |
| 10 | Type the count. Delete is irreversible, so it is confirmed again at the moment it happens (P6) | 1 | 1 | |
| 11 | Confirm | 1 | | |
| | **Total** (visit 1: 7 / 1 / 3; visit 2: 4 / 1 / 2) | **11** | **2** | **5** |

Undo covers disable and move (P5). With "Repeat monthly" on, each later month is visit 2 only, which replaces ME's 12-step automation setup.

**Target: ≤ 33 s across both visits (model 24.9 s + 5 s wait budget = 29.9 s).**
- **Justification.** This is the brief's own example job.
- The two visits keep their safeguards: quarantine comes before delete, and both big batches need deliberate typed confirmation.
- We save the regenerate, re-scope and re-select steps of each ME visit.
- **States to design:**
  - **12,000-row result** at 1,284 selected;
  - the exclusion list (OU, name pattern, OS = server, "do not touch" tag);
  - a computer that becomes active during quarantine is auto-restored and reported;
  - a BitLocker key on a computer about to be deleted. The key objects are children of the computer and are deleted with it, so the sheet warns, and activeDIQ keeps an escrowed copy;
  - a cluster or virtual computer object (CNO/VCO) is excluded by default.

### T18 · Clean up inactive users, excluding service accounts (AD, CMP)

**Frequency (B).**
- CIS v8 5.3: disable dormant accounts after **45 days** ([CIS](https://controls-assessment-specification.readthedocs.io/en/latest/control-5/control-5.3.html)).
- PCI DSS 8.2.6: **90 days** ([MS Learn PCI 8](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-8)).

**ME flow over two visits** ([KB](https://www.manageengine.com/products/ad-manager/admanager-kb/find-and-delete-inactive-ad-user-accounts.html); [report help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html)).
- The KB says to "Explicitly exclude service accounts and other special-purpose accounts", but documents no filter for it.
- We model the exclusion as unticking each one by hand. The scenario has **6 service accounts** among the results.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| | *Visit 1: find, exclude, disable, quarantine* | | | | |
| 1 | Reports tab | 1 | | 1 | doc |
| 2 | "User Reports" | 1 | | | doc |
| 3 | "Inactive Users" (under Logon Reports) | 1 | | 1 | doc |
| 4 | Domain: pre-ticked | 0 | | | demo (me-10 pattern) |
| 5 | Period → 90 days | 2 | | | doc |
| 6 | Tick "Exclude Disabled Users" | 1 | | | doc |
| 7 | Generate | 1 | | | doc |
| 8 | Check All | 2 | | | inferred (as T17) |
| 9 | Untick the 6 service accounts by hand | 6 | | | doc (instruction); mechanism inferred |
| 10 | "Disable" icon. A confirmation opens | 1 | | 1 | doc; confirmation inferred |
| 11 | Confirm | 1 | | | inferred |
| 12 | Ellipsis (…) → move | 2 | | | doc |
| 13 | OU picker: expand, select, OK | 3 | | 1 | inferred |
| | *Visit 2, weeks later: delete from quarantine* | | | | |
| 14 | Reports tab | 1 | | 1 | doc |
| 15 | "User Reports" | 1 | | | doc |
| 16 | "Inactive Users" ("Exclude Disabled Users" stays unticked by default) | 1 | | 1 | doc |
| 17 | "Add OUs": OU picker for the quarantine OU | 4 | | 1 | doc; picker inferred |
| 18 | Generate | 1 | | | doc |
| 19 | Check All | 2 | | | inferred |
| 20 | "Delete" icon. A confirmation opens | 1 | | 1 | doc; confirmation inferred |
| 21 | Confirm | 1 | | | inferred |
| | **Total** (visit 1: 22 / 0 / 4; visit 2: 12 / 0 / 4) | **34** | **0** | **8** | **T = 55.0 s** |

**Pain points**
- Users who sign in over VPN can show as inactive (report help).
- No service-account detection; the KB leaves it to the admin.

**activeDIQ flow.** This is the T17 flow, plus a "Probably service accounts (7)" group that is excluded by default and lists the reason for each. Signals include:
- `servicePrincipalName` set;
- gMSA or sMSA object class;
- "password never expires" combined with no interactive sign-in;
- naming patterns.

In the scenario, the group holds the 6 real service accounts plus 1 false positive.

| # | Step | I | F | S |
|---|---|---|---|---|
| | *Visit 1* | | | |
| 1 | "Clean up" | 1 | | 1 |
| 2 | "Inactive users" card | 1 | | 1 |
| 3 | Expand "Probably service accounts (7)" to check it | 1 | | |
| 4 | Re-include the 1 false positive | 1 | | |
| 5 | Ctrl+A (all matching, service accounts still excluded) | 1 | | |
| 6 | "Quarantine". The plan sheet opens | 1 | | 1 |
| 7 | "Repeat monthly" | 1 | | |
| 8 | Type the count | 1 | 1 | |
| 9 | Confirm | 1 | | |
| | *Visit 2* | | | |
| 10–13 | As T17 steps 8–11 | 4 | 1 | 2 |
| | **Total** (visit 1: 9 / 1 / 3; visit 2: 4 / 1 / 2) | **13** | **2** | **5** |

**Target: ≤ 36 s across both visits (model 27.5 s + 5 s wait budget = 32.5 s).**
- **Justification.** The dangerous part, disabling a service account, is handled by default, with the evidence shown.
- **States to design:**
  - sign-in data from Entra (cloud-only activity) shows the user as active, and both sources are displayed;
  - the user is on leave, via an exclusion tag;
  - the user owns a mailbox shared by others.

### T19 · Export Domain Admins membership, nested, for an auditor (CMP, SEC)

**Frequency (B).**
- PCI DSS 7.2.4: review accounts and privileges "at least once every six months" ([MS Learn PCI 7](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-7)).
- A quarterly SOX cadence is common practice, not law ([Lumos](https://www.lumos.com/identity-matters/identity-access-management/how-to-automate-sox-user-access-reviews)) `[UNVERIFIED as a rule]`.

**ME flow: Group Reports › Detailed Group Members** ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-group-reports.html); [page](https://www.manageengine.com/products/ad-manager/active-directory-group-membership-report.html)). The help says only that the admin "specifies" the group, so the picker steps are `[inferred]`.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Reports tab | 1 | | 1 | doc |
| 2 | "Group Reports" menu | 1 | | | doc; demo (sub-nav, me-10) |
| 3 | "Detailed Group Members" | 1 | | 1 | doc |
| 4 | Domain: preselected | 0 | | | demo pattern |
| 5 | Group: object picker | 5 | 1 | 1 | inferred |
| 6 | Generate | 1 | | | doc |
| 7 | "Export As" → PDF | 2 | | | doc; demo ("Export As" in the report header, me-10) |
| | **Total** | **11** | **1** | **3** | **T = 20.2 s** |

**Pain points**
- The report's name does not say "nested". Only the help explains that it covers "all their nested members by recursively querying the specified groups". The admin has to know it is the one.
- "Reporting is Strong but Sometimes Slow" ([Capterra, Goutam D., 2025-12-09](https://www.capterra.com/p/268487/ManageEngine-AD360/reviews/)).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type "domain admins" | 1 | 1 | |
| 3 | Enter. The group page opens on the Members tab | 1 | | 1 |
| 4 | Toggle "**Effective (nested) · 11**" (the direct count is 4) | 1 | | |
| 5 | Export | 1 | | |
| 6 | PDF | 1 | | |
| | **Total** | **6** | **1** | **2** |

The export is an **evidence pack**:
- the effective-membership path for each member (via which group);
- generated by and at;
- the data freshness time;
- a hash.

**Target: ≤ 16 s (model 12.4 s + 2 s wait budget = 14.4 s).**
- **Justification.** Auditors ask "who has Domain Admin", not for a report name. The evidence pack answers their next question too: "how do they have it?".
- **States to design:**
  - circular nesting is detected and shown;
  - a foreign security principal from a trusted forest;
  - disabled members, which still count and are flagged;
  - data older than the last sync, which shows its age.

### T20 · Schedule a monthly compliance report by e-mail (CMP)

**Frequency (B, C).** This is a rare setup task, included for its stakes (§1.1).
- The schedule is set up rarely and then runs monthly.
- PCI DSS 10.4.1 sets daily log review ([MS Learn PCI 10](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-10)).
- ME schedules run hourly to monthly ([help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-scheduled-reports.html)).

**ME flow: Reports › Schedule Reports, Professional only** (schedule help; [pricing](https://www.manageengine.com/products/ad-manager/pricing-details.html)). The job is to e-mail "password never expires" as PDF on the 1st of each month at 08:00.

| # | Step | I | F | S | Source |
|---|---|---|---|---|---|
| 1 | Reports tab | 1 | | 1 | doc |
| 2 | "Schedule Reports" (top right) | 1 | | 1 | doc; demo (me-10) |
| 3 | "Standard Scheduler" | 1 | | | doc |
| 4 | "+ Create Schedule" | 1 | | 1 | doc |
| 5 | "Schedule Name" | 1 | 1 | | doc |
| 6 | Domain: preselected | 0 | | | doc (drop-down); default inferred |
| 7 | "Select Reports": report-type drop-down | 2 | | | doc |
| 8 | Pick the report in "Available Reports" | 1 | | | doc |
| 9 | "Monthly" | 1 | | | doc |
| 10 | Time drop-down → 08:00 (the day defaults to the 1st) | 2 | | | inferred |
| 11 | Format: PDF | 1 | | | doc |
| 12 | "Email To" | 1 | 1 | | doc |
| 13 | Save | 1 | | | doc |
| | **Total** | **14** | **2** | **3** | **T = 26.1 s** |

**Pain points**
- Scheduling is not in Standard.
- Report UX is the #2 complaint theme (≈17 reviews, CV X2), for example "custom reports … can overflow from the container" ([Capterra, Jacob M., 2026-09-15](https://www.capterra.com/p/143496/ADManager-Plus/reviews/)).

**activeDIQ flow**

| # | Step | I | F | S |
|---|---|---|---|---|
| 1 | `/` | 1 | | 1 |
| 2 | Type "password never expires" | 1 | 1 | |
| 3 | Enter. The report opens with results | 1 | | 1 |
| 4 | "Schedule" in the report header. A sheet opens | 1 | | 1 |
| 5 | Pick the preset "Monthly · 1st · 08:00" | 1 | | |
| 6 | Type the recipient | 1 | 1 | |
| 7 | Save. PDF is the default format | 1 | | |
| | **Total** | **7** | **2** | **3** |

**Target: ≤ 22 s (model 17.0 s + 3 s wait budget = 20.0 s).**
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
| **P1** | **One search, every identifier.** `/` or Ctrl+K from anywhere opens the search overlay. It matches sAMAccountName, UPN, display name, e-mail, employee ID, computer name, BitLocker key ID, group name and report name, and it includes deleted objects. Results carry **status chips**, so many questions are answered without opening anything. Enter opens a deep-linkable object page. | All except T07, T08, T12, T17, T18 |
| **P2** | **The object page is the workspace.** Status, memberships (direct and effective), devices, licences and the History tab ("who/what/when", P5) live on one page. Contextual primary action: a locked account offers "Reset & unlock" first. Each action has a single-key shortcut. **No modal stacks:** at most one side sheet. | T01–T06, T09, T10, T13–T16, T19 |
| **P3** | **Preview before write.** Every change sheet shows exactly what will change: counts, named objects, and side effects such as nesting and licences. Bulk previews summarise first ("300 changes · 12 unchanged"), then list. | T06–T12, T15, T17, T18 |
| **P4** | **Bulk equals single.** Every single action also accepts a selection (filter + Ctrl+A meaning *all matching*, stated in words), a pasted list, or a file. Lists resolve visibly: matched, ambiguous, not found. | T04, T08, T11–T13, T17, T18 |
| **P5** | **Undo and an audit line after every change** (ENH-04). A toast with Undo, for a period set by policy where the operation is reversible. Every change lands in the object's History and in Recent changes as who, what, when and how. Irreversible operations (password, delete past quarantine) say so in the sheet. | All writes |
| **P6** | **Privileged, destructive and secret friction scales with impact.** These need **typed confirmation** (the count, or the object name), plus an approver where policy demands: protected and Tier-0 groups, admin accounts, more than 100 objects, and delete. Secret reveals (LAPS, BitLocker) need a reason plus step-up MFA (TM-D16). Ordinary edits get one Confirm. | T01, T04–T06, T09, T10, T17, T18 |
| **P7** | **Long work runs in the background with honest progress.** Bulk creates, cleanups and big reports never block the console. Partial failure is a designed state: "N of M done, K failed, here is why", with Retry failed, Export failures and Undo batch. | T08, T11, T12, T17, T18 |
| **P8** | **Permission-aware, not permission-hidden.** Out-of-scope objects and actions are visible but disabled, with the reason and who can help. Nothing silently disappears. | All |

**Self-service is out of scope here.** The end-user persona's jobs (reset my own password, unlock myself, update my profile) are ADSSP-parity work in a later milestone (D-0001). They will get their own mobile-first benchmark. Its prerequisite is ENH-03, enrolment without blocking.

## 5. Measurement protocol: how these targets get verified

1. **activeDIQ side.**
   - Once screens exist, script each task in Playwright against the AD lab (T-0012), plus a seeded 12,000-user tier (T-0049).
   - For each task, count I, F and S **by the rules in §1.2**, and record wall-clock time.
   - A design review or QA fails a flow that exceeds its interaction budget (the aDIQ I in §2), or that misses its target by more than 20%.
   - T-0063 automates this. `klm.py` in the evidence folder re-totals §2 whenever a count changes.
2. **ME side.**
   - Re-run the T01, T07, T08, T17 and T19 paths on a **local ME evaluation install**, so we get waits without network distance.
   - Then close the `[UNVERIFIED]` and `[inferred]` items in §6. We will not quote ME waits externally before this is done (ADM §4.2 `[TODO]`).
   - The evaluation download needs registration under a skenzeriq identity, which is an external action. T-0062 does this and must get CEO approval through `ceo-decisions` before it registers.
3. **Pilot side.** Five representative tasks (T01, T03, T08, T09, T17) are timed with real admins at a warm account, in both tools. This feeds the proof point "task-time benchmarks on 10 tasks from customer pilots" (`product-strategy.md`).

## 6. Open items

- `[UNVERIFIED]` / `[inferred]` ME flow details that the docs and the demo did not settle:
  - **T01:** whether ME shows the generated password to the technician; the unlock checkbox's state on a locked account;
  - **T03:** whether AD Explorer's Properties tab shows lock, expiry and last logon together;
  - **T04:** the build-8030 BitLocker "dedicated interface";
  - **T05:** any LAPS reveal or masking;
  - **T06, T07, T10, T11, T19:** the inside of the object-picker pop-up (it did not load within 40 s on the demo);
  - **T08:** per-row failure reasons and retry in place;
  - **T09:** whether the Disable Policy runs when users are disabled from Enable/Disable Users;
  - **T10, T13:** the Modify Single User form's tabs and controls;
  - **T10:** whether "Copy User Attributes" copies `memberOf`, and whether it appends or replaces;
  - **T11:** Group Attributes in Standard, and the CSV match-attribute step;
  - **T12, T17, T18:** whether select-all spans grid pages, and whether the selection survives an action;
  - **T16:** ADAudit Plus 9000 labels;
  - **T17, T18:** confirmation dialogs on Disable, Move and Delete.
- **AD semantics to confirm with the ad-expert in T-0009 review:**
  - T13: what ADUC's "End of <date>" writes to `accountExpires`;
  - T15: password and membership behaviour on tombstone reanimation;
  - T16: the LVR "when and which DC" claim.
- `[UNVERIFIED]` Frequency for T02, T05, T08, T10–T12 and T15. These are replaced by pilot ticket data when it exists.
- `[UNVERIFIED original]` Gartner's "20–50%" and Forrester's "$70 per reset" are quoted second-hand (TechTarget 2011; The Hacker News 2021). Do not use them in external material without the originals.
- `[TODO]` Self-service (end-user) benchmark, when ADSSP parity is scheduled.
- **Runtime targets** are **design budgets**: T08 (validation ≤ 10 s, create ≤ 120 s for 200), the ≤ 1 s per-screen budget, and the step-up window length. The directory-engineer, the solution-architect and the security-architect must confirm them against the AD lab before they go into a spec's acceptance criteria.

## Changelog

- 2026-10-02 · product-designer (T-0008) · First version. 20 tasks benchmarked from:
  - a read-only walk of the ME public demo (build 8041);
  - ME docs;
  - the research corpus.

  Targets were set with the KLM model.
- 2026-10-02 · product-designer (T-0008, review round 1) · Recount and corrections:
  - **Counting rules (§1.2):** made literal for T-0063. The `/` overlay, the step-up prompt, landing pages and confirmations now count as screens. Standard ME pickers are defined. Unknowns favour ME.
  - **ME flows (§3):** every step now has its I/F/S and a source tag. T17 and T18 list both visits. Three new read-only demo captures: me-11, me-12, and the bulk wizard on me-08. A re-total script was added.
  - **Count changes:**
    - T01 now counts ME's shorter "Generate password" path.
    - T06 is now "add one user to one group" on both sides; before, it compared ME's add-and-remove with our add.
    - T07 adds the manager on the ME side, which was missing.
    - T04 and T05 add our own step-up MFA (TM-D16).
    - T15 and T12 come out at parity.
  - **Time model (§1.3):** T is now wait-free on both sides. Targets follow ⌈1.1 × (T + W)⌉, and each task shows that arithmetic.
  - **Totals:**
    - ME is now 278 I / 77 S / ≈513 s (was 301 / 83 / ≈559 s).
    - activeDIQ is now 138 I / 56 S / ≈323 s wait-free (was 129 / 36 / ≈277 s).
    - The time cut is −37% (was −50%), wait-free on both sides.
  - **T08 / Key takeaway 3:** ME's format page accepts DN, sAMAccountName, display name or e-mail for `memberOf` and `manager`. The pain point is now the disagreement with the in-product hint, quoted in full. The earlier quote of the hint had dropped "or Sam Account Name".
  - **AD semantics:** T03 says lastLogonTimestamp only lags ("up to 14 days later"). T13 treats `accountExpires` as a UTC instant. T15 says the Recycle Bin restores the password, and a forced reset applies only to tombstone reanimation or as our policy toggle.
  - **Nits:** Key takeaway 1 now gives per-task figures. LAND, TM and ADSS are defined. T15 and T20 are marked as included for stakes.
