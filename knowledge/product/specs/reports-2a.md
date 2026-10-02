---
title: "Spec: Canned reports at checkpoint 2a: library slice, run, scope, export, schedule"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
author: product-manager
ticket: T-0067
epic: E-012
milestone: M2
parity: [ADM-083, ADM-084, ADM-085, ADM-086, ADM-087, ADM-089, ADM-099, ADM-100, ADM-101]
scope: locked
sources_last_checked: 2026-10-02
---

# Spec: Canned reports at checkpoint 2a

> An admin opens any of the 16 shipped reports from the search box with results already on screen,
> sees exactly how fresh the data is, exports it in two keystrokes and schedules it from the same
> screen, and every row they or a recipient sees is trimmed to the authority of whoever the report
> runs as.

This is the **S4** spec of [m2-plan.md](../../business/scoping/m2-plan.md) §5. It is the input to
T-0099 (run path), T-0100 (remaining definitions), T-0101–T-0103 (export), T-0104 (schedules),
T-0106 (design), T-0114/T-0115 (screens) and T-0116 (proof). It is reviewed by `solution-architect`.

`[DISCOVERY]` marks the choices that were made from research alone because partner discovery has
not come back (m2-plan §4 risk row, §8 Q1). They are the items to re-weight first when it does.

## 1. Problem

Report routines are the daily and monthly rhythm of an ADManager Plus (ADMP) customer. The
switcher-must-have list names them: inactive users and computers, real last logon, locked-out
users, password expiry, nested group membership, empty groups and OS-based computers, exported
and e-mailed on a schedule
([ADMP research §7a](../../business/market-research/manageengine-admanager-plus.md)). If these do
not run, nobody migrates. ADMP's weaknesses are specific, and each is a place to beat it:

- **Stale data.** Reports read a database cache synced from AD every 10 minutes
  ([ADMP research W6](../../business/market-research/manageengine-admanager-plus.md), citing the
  [architecture PDF](https://download.manageengine.com/products/ad-manager/solution-architecture.pdf)).
  In the benchmark, the Inactive Computers report opened on a cached run dated six days earlier
  with a raw `0` in the last-logon column
  ([benchmark, me-09](../../product/specs/top-admin-tasks-benchmark.md)).
- **Too many steps for a routine.** Exporting a group's nested membership takes 11 interactions
  across 3 screens, and scheduling a monthly e-mail takes 14 across 3, in Pro only (benchmark
  T19 and T20).
- **Report UX is the #2 complaint theme**, about 17 reviews
  ([customer voice X2](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
- **Inactive-user cleanup needs hand-ticking of service accounts.** The ME knowledge base says to
  exclude them and documents no filter (benchmark T18, citing the
  [KB](https://www.manageengine.com/products/ad-manager/admanager-kb/find-and-delete-inactive-ad-user-accounts.html)).

## 2. Personas and jobs to be done

| Persona | Job (When… I want… so I can…) | Source |
| --- | --- | --- |
| AD admin | When a cleanup cycle comes round (every 45–90 days), I want the inactive users or computers with the evidence for each, so I can act without hand-checking | Benchmark T17, T18 (frequency from CIS 5.3 and PCI DSS 8.2.6 as cited there) |
| AD admin | When someone asks "who is locked out / whose password expires", I want the answer now and its age stated, so I can trust it | ADMP research §7a |
| Compliance auditor | When I run the periodic access review, I want a group's nested membership with the path for each member, as a file I can hand over | Benchmark T19 (PCI DSS 7.2.4, as cited there) |
| Compliance auditor | When a control needs monthly evidence, I want the report to arrive by e-mail without anyone remembering | Benchmark T20 |
| IT manager | When I want a standing view of password and account hygiene, I want a schedule that e-mails me a short report and stays quiet when there is nothing | ADM-101 "notify only if data" |
| Security/SOC analyst | When I review privileged and stale accounts, I want the report scoped to what I am allowed to see, with exports I can trust | Threat model TB15 |
| Help-desk technician | When I am delegated one OU, I want reports to show that OU only, so I never see data I should not | DM-35, DM-71.I1 |

End users do not touch reports at 2a.

## 3. ManageEngine parity

ME names below come from ME's own
[report list](https://www.manageengine.com/products/ad-manager/active-directory-reports-list.html),
the [user reports help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html)
and the [scheduled reports help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-scheduled-reports.html),
all read on 2026-10-02. Edition and category counts are from the
[ADMP research](../../business/market-research/manageengine-admanager-plus.md) §3.K and the matrix
([feature-parity-matrix.md](../../business/competitive-analysis/feature-parity-matrix.md)).

| Parity ID | What ME does (edition) | Our answer at 2a | Gap, owner |
| --- | --- | --- | --- |
| ADM-083 | Prebuilt library, vendor claims 200+, 12 categories (Std+Pro) | 16 reports in 6 AD categories that answer 54 ME report names through presets (§6). The matrix asks for "fewer, filterable views" | The rest of the AD library follows in the second slice (§12 follow-ups) |
| ADM-084 | User reports (35) (Std+Pro) | USR-01…USR-05: 14 ME names, including Inactive Users, Real Last Logon, Locked-out Users | 21 names deferred (§6.3). "Cannot Change Password" needs the SD read path |
| ADM-085 | Password reports (8) (Std+Pro) | PWD-01…PWD-03: 7 ME names | "Users with Cannot Change Password" deferred (§6.3) |
| ADM-086 | Group reports (16) (Std+Pro) | GRP-01…GRP-04: 15 ME names | Recently Modified/Deleted Groups, Users Only Members of Domain Users Group deferred |
| ADM-087 | Computer reports (18) (Std+Pro) | CMP-01, CMP-02: 10 ME names | BitLocker reports are not stored data (X4); duplicates and managed/unmanaged deferred (§6.3) |
| ADM-089 | Contact and OU reports (13) (Std+Pro) | OU-01, CTC-01: 8 ME names | GPO-linked and blocked-inheritance OUs wait for domain-model Q10 |
| ADM-099 | Scope and filters: several domains, OU scope, period presets, result filters, add or remove columns (Std+Pro) | Fully covered (FR-06, FR-13) | None |
| ADM-100 | Export: CSV, PDF, XLSX, HTML, CSVDE, optional password protection, logo and serial number (Std+Pro) | CSV and XLSX at the 2a demo. PDF and HTML before M2 exit (T-0102) | CSVDE, password-protected export, logo and serial number are a P2 follow-up (§11) |
| ADM-101 | Schedules: hourly, daily, weekly, monthly, custom (minutes to years). Delivery as attachment, ZIP, link, mail body or saved to a path. "Notify only if data". **Pro only** | Every tier. Hourly, daily, weekly, monthly, custom with a 1-hour floor. Attachment, ZIP, link. Notify-only-if-data | Mail-body delivery, save-to-path and minute-level custom are decisions in §11 |

**Not in this ticket's parity list, stated so nobody assumes it:** ADM-092 (other reports),
ADM-093 (compliance sets), ADM-096 (report from CSV), ADM-097 (builder, 2c), ADM-098 (act on
results, 2b), ADM-102 (report-level delegation) and ADM-103 (dashboard widgets). Each is E-012 or
E-011 scope that is groomed at its checkpoint (m2-plan §1). §6.3 lists where ADM-092 reports go.

## 4. What we do better

Four enhancements, each tied to a sourced pain. All four are v1 and in 2a.

| # | Enhancement | ME baseline (sourced) | Target | Proof |
| --- | --- | --- | --- | --- |
| E1 | **Freshness is stated, and exact last logon says how exact it is.** Every run shows when its data was last synced. "Real last logon" reads every DC and shows how many answered. A partial answer is labelled a lower bound and never claims "never logged on" | Cache synced every 10 minutes (W6). Cached run served with a six-day-old date (benchmark me-09). Last logon shown as `0` | No run without an `as_of` and a freshness label (AC-08…AC-11). Real Last Logon matches the maximum over all lab DCs (AC-39) | `qa-verifier` on the lab, T-0116 |
| E2 | **Probable service accounts are excluded by default, each with its reason.** On Inactive Users and the password reports a "Probably service accounts (n)" group is hidden by default and one click shows it | KB: "Explicitly exclude service accounts", no filter documented. Benchmark models 6 manual untick clicks (T18) | 0 manual unticks for the T18 scenario. Every flagged row shows its reason (AC-17, AC-18) | Lab seeded with SPN-bearing and plain users |
| E3 | **Nested membership with the path, as an evidence pack.** The export names, for each member, the group chain it came through, who generated it, when, the data's freshness and a digest | "The report's name does not say nested", only the help does (benchmark T19). Report titles carry no path | T19 in ≤ 6 interactions and ≤ 16 s (§5). The path column is on every effective-membership row (AC-20, AC-27) | Benchmark task T19 re-run in `ux-review` |
| E4 | **Scheduling in every tier, from the report on screen, with presets and per-recipient delivery history.** Recipients outside the tenant's allowed domains need a confirmation and a permission | Pro only (matrix ADM-101). 14 interactions, 3 screens (T20) | T20 in ≤ 7 interactions, ≤ 22 s. Delivery state per recipient visible on the schedule (AC-30…AC-37) | Benchmark task T20 re-run |

Enhancements beyond these (charts, sharing, the builder) are ENH-05 later work (2c) and are not
promised here.

## 5. Experience target

Budgets are the activeDIQ columns of the [benchmark](../../product/specs/top-admin-tasks-benchmark.md)
(interactions / typed fields / screens, counted by its §1.2 rules). They are also the interaction
budget for T-0106 and the `ux-review` targets.

| Task | ME today (benchmark) | Budget | Target time |
| --- | --- | --- | --- |
| Open a report with results (T20 steps 1–3, T19 steps 1–3) | Reports tab, menu, report, domain, **Generate**: 5–6 interactions, 2–3 screens | `/`, type the report or ME name, Enter: **3 / 1 / 2**. No Generate step: defaults run on open | Included in T19 and T20 |
| T19 Export nested membership for an auditor | 11 / 1 / 3, 20.2 s | **6 / 1 / 2** | **≤ 16 s** |
| T20 Schedule a monthly report by e-mail | 14 / 2 / 3, 26.1 s | **7 / 2 / 3** | **≤ 22 s** |
| Export the open report | "Export As", format: 2 interactions | **2 / 0 / 0** (Export, format) | ≤ 3 s of admin time |
| T17 / T18 report visits | 26–34 interactions over two visits | The report half is one card click plus its filters. The act-on-results half is 2b (ADM-098) | Set in the 2b spec |

**The admin never has to:**
- write or paste an LDAP filter (DM-71.I3);
- click Generate to see the default view;
- know which report is the nested one, or that "Real Last Logon" and "Inactive Users" differ;
- tick service accounts off one by one;
- pick a domain before seeing anything (all permitted domains are the default).

**Performance, `[PROPOSED]` defaults for `reporting-engineer` to confirm on the scale tier, T-0116:**
inventory-backed reports show the first 50 rows within 2 s at p95 and the full count within 5 s on
100,000 users. Effective membership of a 6,000-member nested group shows its first page within 5 s.
Per-DC reports run as a visible background job (§6.5) and never block the page.

### Flow A. Run, export, schedule (primary)

| # | Actor does | System shows | Pattern |
| --- | --- | --- | --- |
| 1 | Presses `/`, types "inactive users" (or an ME name such as "Recently Logged on Users") | Report matches, each with its category. An ME name shows "Logon activity · preset Recently Logged on Users" | Search overlay |
| 2 | Presses Enter | The report opens on the default preset with the first page already on screen. The header reads: scope applied, freshness label, row count, preset chips, **Export**, **Schedule** | Data table over a report header |
| 3 | Adjusts a preset chip, period or one column filter | The grid refreshes in place. The URL holds the state, so the view can be shared (the data is still trimmed per viewer) | Filter bar, column chooser |
| 4 | Clicks **Export**, then a format | The file is prepared as a job. A toast links the stored artefact. Row count and format appear in the run's history | Menu, toast |
| 5 | Clicks **Schedule** | A side sheet opens with the report, filters and columns as they are on screen, and presets (Daily 08:00, Weekly Monday 08:00, **Monthly 1st 08:00**) | Side sheet |
| 6 | Picks the preset, types a recipient, clicks Save | Save runs the `reports.schedule.create` Action inline (ADR-0005 rule 10): the preview diff, including any external-recipient confirmation (§8.4), is the sheet's last step. The schedule then appears under Schedules with next run, owner, recipients and state | Sheet, then list |

### Unhappy paths

- **No permission.** A user without `reports.run` sees no Reports entry and no search hits for
  reports. A user with it but with no scope sees the empty state "Your role covers no directory
  objects. Ask an administrator to grant a scope" and zero rows, never an error.
- **A connection has never synced.** The report does not run for it. The header says "Not synced
  yet: <connection>" and the run completes for the others.
- **Data is stale.** Runs, with a banner naming the age and the cause (§6.2).
- **DC unreachable on a per-DC report.** The run completes with partial coverage, naming the DC
  and the error (§6.5).
- **Run fails.** The run record shows state `failed`, a typed reason and a retry button.
- **Row cap reached.** Refuses to export, names the count and the cap, and offers CSV or narrower
  filters. It never truncates silently (§8).
- **100,000 objects.** Server-side paging, sorting and filtering. The grid is virtualised. The
  count appears without loading every row.
- **Empty result.** "No users match. 12,431 users were checked in 3 domains as of 09:41", and the
  filters offered for removal. Never a blank grid.

## 6. The 2a library

### 6.1 Rules for the library

1. Shipped reports are **definitions**, not code: an AST over one dataset (DM-71, blueprint §10).
   They are immutable. A custom variant is a clone (DM-71.I2), and cloning is the 2c builder.
2. A **preset** is a named set of filters, a period and a column set over a report. Each ME name in
   §6.2 is a preset. Presets are data in the definition version, so MIG-05 can import ME names
   without code.
3. The library groups reports in six categories: Users, Passwords, Groups, Computers, Contacts,
   Organizational units. Searching the library or `/` also matches the ME names listed against each
   report, shown as "Also known as" (FR-02).
4. Default periods and thresholds: **inactive after 90 days**, "recent" is 30 days, "soon to
   expire" is the next 14 days. The minimum inactivity threshold on a replicated logon time is
   30 days (§6.4). ME's own default is "Last 30 days" (benchmark me-09), which would flag live
   accounts, so ours is deliberately longer.
5. Every column in §6.2 exists in the dataset registry (DM-70). A column can be added or removed
   from the grid by the admin (ADM-099) but never a column the registry does not carry.
6. Objects in state `deleted` or `purged` (DM-16 lifecycle) are not in any 2a report. The "Recently
   Deleted" family is deferred to the second slice.
7. All 2a reports are AD only. Entra objects arrive with the hybrid slice (2c, §11).

### 6.2 Report table with ME crosswalk

Datasets are named in §7. "Replicated logon" means `lastLogonTimestamp`. Dates show in the viewer's
time zone with the zone label. Names in the "ME names" column are exact as listed by ME.

**Users (ADM-084)**

| ID | Report | ME names (presets) | Dataset | Default columns | Default filters |
| --- | --- | --- | --- | --- | --- |
| USR-01 | Users | All Users · Enabled Users · Disabled Users · Users Without Managers · Recently Created Users | `inventory.users` | Name, Logon name, UPN, Status, Domain, OU path, Manager, Created | None (all live users). Presets: status = enabled / disabled; manager is empty; created in the last 30 days |
| USR-02 | Account expiry | Account Expired Users · Recently Account Expired Users · Soon-to-expire User Accounts · Account Never Expires Users | `inventory.users` | Name, Logon name, Domain, OU path, Account expires, Days to / since expiry, Status | Default preset: expired. Recently: expired in the last 30 days. Soon: expires in the next 14 days. Never: no expiry (`accountExpires` 0 or max, DM-16 codec) |
| USR-03 | Logon activity | Inactive Users · Recently Logged on Users · Users Never Logged On | `inventory.users` | Name, Logon name, Domain, OU path, Last logon (replicated), Days since, Created, Status, Probable service account | Default preset: Inactive 90 days, enabled accounts only, probable service accounts hidden. Recently logged on: last 30 days. Never: no replicated logon value (§6.4 caveat shown on the preset) |
| USR-04 | Real last logon | Real Last Logon | `inventory.users` + per-DC read | Name, Logon name, Domain, OU path, Real last logon, From DC, DC coverage, Days since, Status | Enabled accounts. Includes read-only DCs by default. Needs a scope within the read cap (§6.5) |
| USR-05 | Locked-out users | Locked-out Users (ME's help writes it "Locked-Out Users" in one place) | `inventory.users` | Name, Logon name, Domain, OU path, Locked out since, Lockout ends, Policy source, Data as of | Currently locked out (computed, §6.4) |

**Passwords (ADM-085)**

| ID | Report | ME names (presets) | Dataset | Default columns | Default filters |
| --- | --- | --- | --- | --- | --- |
| PWD-01 | Password status | Password Expired Users · Soon-to-expire User Passwords · Users with Password Never Expires · Users with Change Password at Next Logon | `inventory.users` | Name, Logon name, Domain, OU path, Password last set, Password expires, Password state, Policy source, Status, Probable service account | Default preset: expired. Soon: expires in the next 14 days. Never expires: state is either "never (account flag)" or "never (policy)". Must change: state is "must change at next logon". Probable service accounts hidden on expired and soon |
| PWD-02 | Password age | Password Changed Users · Password Unchanged Users | `inventory.users` | Name, Logon name, Domain, OU path, Password last set, Days since, Status | Changed: last 30 days. Unchanged: not changed in 90 days. Enabled accounts only on Unchanged |
| PWD-03 | Recent logon failures | Recent Logon Failures. ME's list also has "Recently bad logged users", whose equivalence is `[UNVERIFIED]` (research ticket, §12) | `inventory.users` + per-DC read | Name, Logon name, Domain, OU path, Last failed logon, From DC, Failures on that DC, DC coverage | Failed in the last 7 days. The count is per DC because `badPwdCount` is per DC (connector-contract §5.5). It is never summed |

**Groups (ADM-086)**

| ID | Report | ME names (presets) | Dataset | Default columns | Default filters |
| --- | --- | --- | --- | --- | --- |
| GRP-01 | Groups | All Groups · Security Groups · Distribution Groups · Group Type and Scope · Groups Without Members · Managed Groups · Unmanaged Groups · Top N Big Groups · Recently Created Groups | `inventory.groups` | Name, Domain, OU path, Type, Scope, Direct members, Effective members, Managed by, Created | None. Presets: type; no members, counting primary-group members (§6.6); managed-by set / not set; Top N = sort by effective members descending, N = 25; created in the last 30 days |
| GRP-02 | Group members | Group Members · Detailed Group Members · Users in Groups | `inventory.group_members` | Group, Member, Member type, Domain, OU path, Status, Membership kind, Via | **Requires one or more groups.** Group Members: direct members. Detailed Group Members: effective members with the Via path. Users in Groups: effective, users only. A switch "Exclude nested groups" is ME's wording and equals direct |
| GRP-03 | Groups for users | Groups for Users | `inventory.group_members` | User, Group, Group type, Group scope, Membership kind, Via | **Requires one or more users.** Effective, including the primary group |
| GRP-04 | Not in any group | Users Not in Groups · Computers Not in Groups | `inventory.users`, `inventory.computers` | Name, Domain, OU path, Primary group, Status, Created, Last logon (replicated) | Preset chooses users or computers. Definition and domain coverage in §6.6 |

**Computers (ADM-087)**

| ID | Report | ME names (presets) | Dataset | Default columns | Default filters |
| --- | --- | --- | --- | --- | --- |
| CMP-01 | Computers | All computers · Enabled Computers · Disabled Computers · Workstation Computers · Domain Controllers · Computers Trusted for Delegation · OS based computers · Recently Created Computers | `inventory.computers` | Name, DNS name, Domain, OU path, Type, Operating system, OS version, Status, Delegation, Created | None. Presets: status; type = workstation (OS name has no "Server" and not a DC; `[UNVERIFIED]` that ME means this); type = domain controller (`SERVER_TRUST_ACCOUNT`, read-only DCs labelled); delegation is not "none"; OS filter by name; created in the last 30 days |
| CMP-02 | Computer activity | Inactive computers · Active Computers | `inventory.computers` | Name, DNS name, Domain, OU path, Operating system, Last activity, Activity source, Days since, Status, Created | Default preset: Inactive 90 days, enabled only. gMSA and cluster objects are excluded and counted in the header (§6.4). Active: activity in the last 30 days |

**Contacts and OUs (ADM-089)**

| ID | Report | ME names (presets) | Dataset | Default columns | Default filters |
| --- | --- | --- | --- | --- | --- |
| OU-01 | Organizational units | All OUs · Empty OUs · Users-Only OUs · Computers-Only OUs · Recently Created OUs | `inventory.ous` | Name, Domain, Path, Users, Computers, Groups, Other objects, Objects in subtree, Created | Empty: no objects other than OUs in the subtree. Users-only: the subtree holds at least one user and nothing else but OUs. Computers-only: likewise. Recently created: last 30 days |
| CTC-01 | Contacts | All Contacts · Mail Enabled Contacts · Recently Created Contacts | `inventory.contacts` | Name, E-mail, Domain, OU path, Created | None. Mail enabled = the `mail` attribute has a value (`[UNVERIFIED]` against ME's meaning) |

The 16 reports above answer **54** ME names: USR 14, PWD 7, GRP 15, CMP 10, OU 5, CTC 3.

### 6.3 ME names not in 2a, and where each goes

| ME names | Why not at 2a | Goes to |
| --- | --- | --- |
| Recently Modified / Recently Deleted (Users, Groups, Computers, Contacts, OUs) | `whenChanged` is a per-DC value that is not replicated, so "modified" needs the observation history (DM-18.I2). Deleted visibility defaults are T-0065 scope | Second slice (follow-up ticket, §12) |
| Users with Cannot Change Password | The truth is two deny ACEs on the object, not the `userAccountControl` bit. It needs the security-descriptor read path ([Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties), [reading the ACEs](https://learn.microsoft.com/en-us/windows/win32/adsi/reading-user-cannot-change-password-ldap-provider)) | Second slice, after T-0118 |
| Bitlocker Recovery Keys, Bitlocker Enabled / Disabled Computers | Recovery values are secrets and are never stored (X4, TM-TB15-T3). Enabled/disabled needs the `msFVE` child objects, which are not in the synced set. A single-key lookup is ENH-01 / benchmark T04 | 2b (AD Explorer and `ReadSecret`) |
| Photo Based, Dial-in Allow/Deny, Users with/without Logon Script, Skype/Lync Enabled/Disabled, Smart Card Enabled, Logon Hour Based, Terminal Services (2), Users with Empty / Duplicate Attributes, All Managers, Manager Based Users, Users in More than One Group, Users Only Members of Domain Users Group, Computers with Duplicate Attributes | Lower use. They need attributes outside the 2a sync set or grouping logic | Second slice |
| Managed Computers, Unmanaged Computers | ME's meaning is not in the research | Research ticket (§12), then second slice |
| GPO Linked OUs, GPO Blocked Inheritance OUs | Needs `gPLink` and `gPOptions` handling (domain-model Q10) | 2b with E-008 |
| Password Policy, Account Lockout Policy, Printer Reports, DC Replication Status, Lingering Objects (ADM-092) | Different datasets | Second slice |
| Exchange, GPO, NTFS/Permissions, M365, Google Workspace report families (ADM-088, 090, 091, 094, 095) | Matrix priority P2–P4 | Their milestones |

### 6.4 Derived states: computed at read time (DM-16.I5a)

`locked_out`, `password_expired`, `password_expires_at` and `account_expired` are **never stored as
flags**. A lockout expiring or a password expiring involves no directory write, so sync never sees
it. Each is computed when the report runs, from the stored inputs and the effective policy, and the
report row carries the inputs' `observed_at`. The rules come from the `ad-expert` consult
(2026-10-02) and the MS-ADTS definitions; the rows below are what the reports must implement.

**Locked out** ([`msDS-User-Account-Control-Computed`, MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2)).
A user is locked out when all of these hold:
1. none of `WORKSTATION_TRUST_ACCOUNT`, `SERVER_TRUST_ACCOUNT`, `INTERDOMAIN_TRUST_ACCOUNT` is set,
   so computer accounts are never "locked out";
2. `lockoutTime` is not 0;
3. the effective lockout duration is "until an admin unlocks" (stored 0), or `now` is before
   `lockoutTime` plus the duration.

The effective duration is the PSO's `msDS-LockoutDuration` when the user has a resultant PSO,
else the domain's `lockoutDuration`
([MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6da47028-e678-475e-b015-a5a15ee98212)).
`lockoutTime` is never cleared when a lockout lapses
([lockoutTime](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lockouttime)), which is why
a stored flag would be wrong. Lockout is processed on the PDC emulator, so a replica can briefly
hold a stale value: the row shows "as of <time> from <DC>".

**Password state**, evaluated in this order ([MS-ADTS PE bit](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2),
[MS-ADA3 `pwdLastSet`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/9663282b-c880-4061-ba8e-e8509c8aa336)):

| Order | Condition | State shown |
| --- | --- | --- |
| 1 | Computer, trust or other non-user account | Not applicable |
| 2 | `DONT_EXPIRE_PASSWORD` is set (even when `pwdLastSet` is 0) | Never expires (account flag) |
| 3 | `SMARTCARD_REQUIRED` is set | Not applicable (smartcard required) |
| 4 | `pwdLastSet` is 0 or absent | **Must change at next logon**. Never labelled "expired" |
| 5 | Effective maximum password age is "never" | Never expires (policy) |
| 6 | `pwdLastSet` plus the effective maximum age is before now | **Password expired** |
| 7 | Otherwise | Expires on that date (shown with days remaining) |

The effective maximum age is the PSO's `msDS-MaximumPasswordAge` if a PSO applies, else the domain's
`maxPwdAge`. The codec treats stored 0 and the minimum signed 64-bit value as "never".

**Evaluated in the query, not after it.** `locked_out`, `password_state`, `password_expires_at` and
`account_expired` are **dataset columns of `inventory.users`, evaluated inside the compiled query**,
with `now` and the resolved policy values bound as arguments. They are never a post-filter or a
loop in application code. This is what makes filter, sort, total count and paging (FR-12) and the
post-trim counts (LF-39) correct: a "Locked-out Users: 37" count is the count of rows the
predicate selects. The registered-column contract is `solution-architect`'s, tracked in T-0182,
and the build tickets cite it.

**Missing inputs.** If an input was not read, a PSO could not be resolved or read was denied, the
state is **Unknown (input missing)** with the reason on hover. A report never infers "not locked" or
"not expired", and never silently falls back to the domain policy when the PSO is unresolvable.

**Policy source** shows "Domain policy" or the PSO's name. A PSO can change without any write to
the user (a group membership change or a PSO edit), so the effective policy is **resolved at run
time from the synced policy objects**, and no per-user cached PSO decides a report (§7 requirement
D4).

**Replicated logon (`lastLogonTimestamp`).** It is written only when the stored value is older than
`msDS-LogonTimeSyncInterval` (default 14 days, effective 9–14), so it lags
([attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp),
[AskDS](https://learn.microsoft.com/en-us/archive/blogs/askds/the-lastlogontimestamp-attribute-what-it-was-designed-for-and-how-it-works)).
Consequences the reports must honour:
- the column heading says "(replicated)" and the report header says "accurate to the sync
  interval";
- a threshold below 30 days is not offered on these reports. The domain's interval is read per
  domain, and if it is 0 the report is disabled for that domain with a message;
- an **absent** value means "no qualifying logon was recorded", which is not proof of "never logged
  on". The Never Logged On preset carries that caveat, and USR-04 is the exact answer. RODC-served
  logons may not have reached a writable DC
  ([RODC behaviour](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd736126(v=ws.10)));
- smartcard-only and Kerberos-only logons are `[UNVERIFIED]` `[LAB: Windows]` (domain-model note).

**Computer activity (CMP-02).** "Last activity" is the later of the replicated logon and
`pwdLastSet`, with "Activity source" saying which won. This is a heuristic, not a Microsoft
definition `[UNVERIFIED as a Microsoft definition]`. The report states its caveats in the header:
- a machine-account password also changes on an admin reset or a rejoin, which is not device
  activity;
- Samba and other Linux joins rotate on their own schedule
  ([smb.conf](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html), default 7 days for
  winbind), so an unrotated join looks stale;
- gMSA and cluster objects are excluded from Inactive and shown as a count with a link;
- if both values are absent or `pwdLastSet` is 0, the activity falls back to `whenCreated`.

### 6.5 Per-DC reports: USR-04 and PWD-03

`lastLogon`, `logonCount`, `badPwdCount` and `badPasswordTime` are not replicated. Their truth is
per DC, and the connector's contract is `ReadPerDC{ObjectRef, attrs}`, one object per call
([blueprint §7.1](../../development/architecture/blueprint.md),
[connector-contract §5.5](../../development/architecture/connector-contract.md)). The inventory
holds only the replicated values, so these two reports have two stages:

1. **Candidates.** Compile the preset's filters over `inventory.users`, trimmed to the runner's
   scope. This gives the candidate objects and an estimate of reads (candidates × DCs in scope).
2. **Read.** Obtain every in-scope DC's value for each candidate. **How** (a live read per object,
   a batched read, or a stored per-DC dataset refreshed by a sweep) is not decided here: it is
   the ADR in T-0181. What the report requires is the result: one value per DC, the maximum, the
   DC it came from, and `PerDcSummary{dcs_in_scope, dcs_answered, coverage}`, with the freshness
   label of §8.2.

Rules:
- **Coverage is always shown** ("Read from 5 of 6 DCs · 1 unreachable: <DC>: <error>"). `COMPLETE`
  only when every DC in scope answered.
- With `PARTIAL` coverage, the maximum is a **lower bound**. The column becomes "Last logon (at
  least)", and a user with no logon on the answered DCs shows "Not confirmed", never "never".
- **Read cap.** Before any read, the run estimates candidates × DCs. Above the cap (`[PROPOSED]`
  250,000 per-object-per-DC reads per run; T-0181 sets the unit if the mechanism changes it) it refuses and says "This run would read 41,200 accounts from 6 DCs.
  Narrow the scope or filters", naming the cap (TM-TB3-T8 and TM-TB15-T8 bound DC load).
- Read-only DCs are included by default (`PER_DC_SCOPE_ALL`). A switch excludes them
  (`WRITABLE`).
- These runs are jobs with progress and are cancellable. Results are stored like any run.
- A per-DC report **cannot be scheduled more often than daily**, to protect DCs (§9).
- `[LAB: Windows]` Per-DC attributes behave the same on Samba for reads, but lockout, PSO and
  computed-attribute behaviour on Samba is `[UNVERIFIED]`; a green Samba test is not proof for them
  (§10 note).

### 6.6 Groups: effective membership and "not in any group"

Effective membership comes from the stored link edges (DM-17), never from a live recursive LDAP
walk:
- the **primary group** (`primaryGroupID`) counts as a membership of kind "primary group". It is
  absent from `member`, so it is derived
  ([primaryGroupID](https://learn.microsoft.com/en-us/windows/win32/adschema/a-primarygroupid));
- group nesting may cycle (DM-17.I3). The traversal keeps a visited set. A cycle is listed as a
  finding row "Circular nesting: A → B → A" and never loops or hides members;
- a foreign security principal is shown as "External principal (unresolved)" with its SID, and is
  not expanded unless that forest is a connection (DM-17.I4);
- a member from another domain of the same forest is an ordinary row;
- **domain coverage:** the header lists the domains the run covered. A group whose members live in
  a domain outside the runner's scope or the inventory is flagged "includes members outside the
  covered domains";
- **Groups Without Members** counts members through `member` and through `primaryGroupID`, so a
  group whose only members are primary-group users is not reported as empty;
- **Not in any group** means: the object is a member of no group other than its primary group,
  across every domain inventoried. A user whose primary group is not "Domain Users" shows that
  group in the Primary group column. The header lists the domains covered, because a per-domain
  `memberOf` can miss a cross-domain universal group
  (`ad-expert` consult, 2026-10-02).

### 6.7 Probable service accounts (E2)

A user is "probable service account" when it has a `servicePrincipalName` **or** both
`DONT_EXPIRE_PASSWORD` is set and its logon name matches a tenant-editable pattern list. The
default list is empty at install, so the default signal is the SPN. Signals come from the benchmark's
T18 list (SPN, never-expires password, naming pattern). Rules:
- on USR-03 (Inactive Users) and PWD-01 (expired and soon-to-expire) the group is **hidden by
  default** and the header says "7 probable service accounts hidden · Show";
- every flagged row shows its reason ("servicePrincipalName set"); none is deleted from the data;
- the label says **probable**: the report never claims certainty. A false positive is one click to
  include;
- the signal set belongs to the definition version, so changing it is a new version (X7).

## 7. Datasets the reports need

Datasets are registered on EP-8 by `directory/inventory` (DM-70). This table is the requirement the
2a reports place on them. The spec for the tables themselves is T-0065 and the build is T-0091. Any
row marked **new** is not yet in their scope and is sent to them as a note.

| ID | Dataset | Rows | Columns the reports need (registered, typed, pre-quoted) | Scope column | Freshness source |
| --- | --- | --- | --- | --- | --- |
| D1 | `inventory.users` | user and inetOrgPerson objects, state `live` | GUID, connection, domain, `dn` snapshot, OU path, `sAMAccountName`, UPN, display name, `userAccountControl` flags decoded, manager (GUID + display), `whenCreated`, `lockoutTime`, `pwdLastSet`, `accountExpires`, `lastLogonTimestamp`, `servicePrincipalName` present, `primaryGroupID`, effective-policy inputs (D4), `observed_at` | `ancestry` | NC sync watermark |
| D2 | `inventory.computers` | computer objects (gMSA identified by class) | GUID, domain, name, DNS hostname, OS name, OS version, `userAccountControl` flags, delegation inputs (unconstrained flag, `msDS-AllowedToDelegateTo` present), `lastLogonTimestamp`, `pwdLastSet`, `whenCreated`, `primaryGroupID`, `observed_at` | `ancestry` | NC sync watermark |
| D3 | `inventory.groups`, `inventory.group_members`, `inventory.ous`, `inventory.contacts` | groups, edges derived from DM-17 plus primary-group edges, OUs with per-kind child counts, contacts | Group type and scope from `groupType`, `managedBy`, direct and effective counts, edge kind and path, OU subtree counts per class, contact `mail` | `ancestry` of the owner object | NC sync watermark |
| D4 | Policy inputs (**new**) | domain password and lockout policy, PSOs, PSO links | `maxPwdAge`, `lockoutDuration`, `msDS-LogonTimeSyncInterval` per domain; PSO values and `msDS-PSOAppliesTo`; precedence rules. Resolved at run time, so a PSO edit or a group change is reflected without any write to the user | n/a | Policy read time |
| D5 | Per-DC read (**not a stored dataset**) | `ReadPerDC` result for a GUID set | per DC: `lastLogon`, `badPwdCount`, `badPasswordTime`, `Observation` | n/a | Read time, per DC |

**Requirements sent to T-0065 and T-0091** (also recorded as notes on those tickets):
- **D6.** Each covered naming context needs a **last successful sync pass** time distinct from
  `last_change_at`. A quiet directory has no changes, and using `last_change_at` would label a
  healthy, quiet domain "Stale".
- **D7.** DM-16's input list must carry `userAccountControl` (trust, smartcard and
  `DONT_EXPIRE_PASSWORD` bits), `primaryGroupID` and `whenCreated`, plus D4 (from the `ad-expert`
  consult). A follow-up ticket asks `ad-expert` to amend DM-16 (§12).
- **D8.** Secret attributes are never in a dataset (X4, LF-38). No report column can name one.
- **D9.** Scope is applied by the compiler from a T-0089 `ScopePredicate` produced only by T-0094
  (m2-plan §2 decision 4). Reports never build a scope.

## 8. Run, scope, freshness and export rules

### 8.1 Run and scope

- **Scope the admin sets (ADM-099).** Connections/domains: multi-select, default every domain the
  runner's scope reaches. OUs: include and exclude pickers, subtree or one level. Period: presets
  of 7, 30, 90, 180 and 365 days plus a custom range. Typed filters per column. The admin can add
  and remove columns.
- **Authority the system applies (DM-71.I1).** The runner's scope is applied inside the query.
  Counts, page totals and the "checked n objects" text are computed after trimming (DM-35.I4,
  LF-39). Sharing a view link never shares data.
- **2a scope kinds.** Only `naming_context`, `ou_subtree` and `ou_one_level` exist (T-0094). A
  role whose scope uses `group_members` or an Entra kind grants **nothing** in 2a reports, and the
  empty state names the reason. Reports fail closed on any scope kind they do not understand.
- **What a run is.** A run is one execution of a report over one frozen set of inputs. Changing the
  preset, a filter, the period, the scope or the column set **creates a new run**. Paging and
  sorting read **the same run's stored result** and never re-execute against newer data. The
  header's `as_of`, freshness label, row count and digest belong to the run on screen. Export and
  scheduled delivery **serialise that run's stored result**, so the exported rows, the About block
  and the digest equal what the admin saw for that run. A scheduled fire creates its own run, and
  its files serialise that run. Exporting a run whose result has expired (§8.1 retention) re-runs
  it first and says so, and the file carries the new run's `as_of`.
- **Run record (DM-72).** Every run stores the definition version (X7), parameters, runner,
  `scope_applied` (a human-readable summary, shown in the header), `as_of`, row count, state and
  result. States: `queued → running → succeeded | failed | cancelled`, then `succeeded → expired`.
- **Retention.** Stored results and exports expire after 7 days by default (`[PROPOSED]`, tenant
  setting 1–30 days). An expired result is re-run on demand, never served as current.

### 8.2 Freshness labels (DM-72.I1)

The header shows one of these. "Live" appears only where a report reads DCs.

| Label | When | What happens |
| --- | --- | --- |
| **Synced 09:41** | Every covered NC's last successful sync pass is within the staleness threshold T-0065 sets | Runs |
| **Stale: last sync 3 h ago (<connection>)** | A covered NC is older than the threshold, in `resync_required` or paused | Runs, with a banner naming the age and cause. Exports and schedules carry the label |
| **Not synced yet** | A connection has no completed first sync | Runs for the others. This connection is listed as skipped |
| **Read from 5 of 6 DCs at 09:43** | USR-04 and PWD-03 | As §6.5 |

`as_of` on the run is the **oldest** watermark among the NCs covered. A computed state also shows
the time it was computed.

### 8.3 Export

| Rule | Value |
| --- | --- |
| Formats at the 2a demo | **CSV, XLSX** (T-0101) |
| Formats by M2 exit | + **PDF, HTML** (T-0102). The UI offers only formats that exist (no dead options) |
| Not in this spec | CSVDE, password protection, logo (§11) |
| Content | The columns on screen at export time, the filters applied, and the full result, not just the visible page |
| Encoding | Only the P7 output encoders ([safe-primitives §12](../../development/architecture/safe-primitives.md)). CSV is TAB-in-quotes formula neutralisation, XLSX uses typed string cells and `quotePrefix`. No raw writer (TM-TB15-T1) |
| "About" block | XLSX: a first sheet. PDF and HTML: a header. Both carry report and preset, scope applied, filters, freshness, DC coverage, generated by and at, row count and the result digest. **CSV carries none**, so it stays a clean table. The same facts are in the run record and the audit event |
| Digest | SHA-256 over the canonical form below, taken from the run's stored result (not the file, which cannot contain its own hash). Shown on the run record, the audit event and the About block |
| File name | `<report>-<preset>-<yyyymmdd-hhmm>Z.<ext>`, built by the download-header encoder |
| Time | CSV: ISO 8601 UTC. XLSX: typed date cells. PDF and HTML: the owner's or runner's time zone with the zone label |
| Evidence pack (E3) | On GRP-02 effective views the About block adds the effective-membership summary (direct n, effective m, cycles found) and every row carries Via |
| Storage | A tenant-prefixed blob that expires (DM-72.I3), downloaded only through an authenticated request. An expired file returns **410 Gone**. The owner can delete one early |
| Secrets | A column that names a secret attribute cannot exist (D8) |

**Canonical form for the digest.** One definition, implemented once in `platform/export` (T-0101)
and used by every format and by the run record. Input: the run's rows in **run order** (the run's
sort, with the row key, the object GUID or edge key, as the final tie-break), restricted to the
**exported columns in their exported order**. Encoding: first the ordered list of column IDs, then
every row; every value is `type tag (1 byte) ‖ length (4 bytes, big-endian) ‖ bytes`, so no
concatenation is ambiguous. Typed text forms: string = UTF-8 as stored; integer = base-10; boolean
= `true` or `false`; time = RFC 3339 in UTC with `Z` and whole seconds; enum = its stable ID, not its
label; absent value = its own tag with length 0 (distinct from the empty string). The digest is
over typed values, so it does not change with CSV or XLSX formatting or the viewer's time zone.
Anyone can recompute it from the run's rows through the API.

**Row caps (TM-TB15-T8)**, `[PROPOSED]` defaults for `reporting-engineer` to confirm on the scale
tier. A tenant can lower a cap and never raise it above the hard value:

| Limit | Default |
| --- | --- |
| Rows stored per run | 1,000,000 |
| CSV rows | 1,000,000 |
| XLSX data rows | 1,000,000 (the XLSX sheet limit is 1,048,576 rows including the header) |
| PDF rows | 5,000 |
| HTML rows | 20,000 |
| Per-DC reads per run | 250,000 (§6.5) |
| Concurrent report jobs per tenant | 4, and 1 per schedule |
| Recipients per schedule | 50 |

Behaviour at a cap is always **refuse and explain**: "This export has 1.4 million rows. CSV allows
1,000,000. Narrow the filters", offering a narrower filter or another format. A silent truncation
is a defect (AC-24). Encoders stream. Exports run as asynchronous jobs.

### 8.4 Schedules

A schedule is a recurring run plus delivery (DM-73). It uses the shared Schedule shape (DM-44).

- **Recurrence.** Hourly (every n hours), daily, weekly (days), monthly (day of month or last day),
  custom (a start and a repeat in hours, days, weeks or months). **Minimum interval is 1 hour.**
  Time zone is an IANA zone and is part of the schedule. A local time skipped by DST runs at the
  next valid instant, a repeated one runs once, and after downtime a missed schedule runs **once**,
  never as a burst (DM-44.I1, I2). Presets: Daily 08:00, Weekly Monday 08:00, Monthly 1st 08:00.
- **What it runs.** The report, preset, filters, columns and scope exactly as on screen when saved,
  pinned to the definition version (X7).
- **Delivery.** E-mail through `notify`. Per recipient, the schedule picks formats and either
  **attachment** (one file, or a ZIP when there are several files) or **link**. A link points at
  the stored artefact and is not offered for an external address. **Link rule (one rule):** a link
  is downloadable **only by the named recipient account, signed in, and holding `reports.export`**.
  It serves the **same owner-scope artefact an attachment would**, byte for byte (the digest
  matches), not a re-run under the recipient's scope. A recipient whose own scope is narrower
  therefore receives the owner's wider data: that is the accepted TM-TB15-T2 residual, and it is
  why the sheet states "recipients receive what the owner can see". Any other account, including one
  holding `reports.export`, and any signed-out request is refused. Every download is audited
  (§8.6). A link expires with the artefact (410). Attachments larger than the configured limit
  (default 10 MB, `[PROPOSED]`) go as a link to account recipients and fail the delivery for
  external ones, with the reason shown.
- **Notify only if data.** An option. When on, a run with zero rows records the run and sends
  nothing. The schedule list shows "ran, nothing to send".
- **Recipients.** Accounts (activeDIQ users) or e-mail addresses. An address whose domain is not on
  the tenant's **allowed recipient domains** list is *external* (the list is empty at install, so
  every address is external until an admin adds domains, a secure default). External delivery needs
  the `reports.deliver.external` permission (DM-73.I2) and a visible confirmation "Data leaves your
  organisation: <address>". The scheduled report's data is what the **owner** could see, which the
  sheet states beside the recipient list (TM-TB15-T2, TM-TB18-T9).
- **Owner authority at run time (DM-73.I1).** DM-73.I1 covers every permission, not only
  `reports.run`. At every fire the report compiles with the owner's scope and permissions **as they
  are at that moment**, and the fire checks, in this order:
  1. *Owner state.* If the owner is disabled or deleted, or no longer holds `reports.run`,
     `reports.export` or `reports.schedule`, the schedule **pauses** with the reason shown, tenant
     owners are notified, and nothing is sent.
  2. *Scope.* If the owner's scope shrank, the run uses the smaller scope and its record shows the
     scope applied. No run uses a cached scope.
  3. *Each recipient.* Whether an address is external is **re-evaluated against the current allowed
     recipient domains list**, not the list as saved. For each address that is external now, the
     owner must hold `reports.deliver.external` now. Where the owner does not, **that recipient's
     delivery fails with the reason** "owner lacks external delivery permission" (or "address is no
     longer in an allowed domain"), is shown on the schedule and notifies the owner. **The schedule
     does not pause** and every other recipient is delivered. An address that became internal needs
     no check and is delivered. An account recipient is checked for holding `reports.export` when a
     link is used.
- **Reassigning the owner** needs `reports.schedule.manage_all`. The schedule pauses until the new
  owner resumes it after seeing the recipient list, so a reassignment cannot widen what recipients
  receive without the new owner's act.
- **Delivery tracking (E4).** Each recipient has its own state (DM-84): queued, sent, failed with
  retries, given up. The schedule page shows the last runs and per-recipient state. A failed
  delivery notifies the owner after retries are exhausted.
- **Per-DC reports** (USR-04, PWD-03): not more often than daily.
- **Configuration writes are Actions (ADR-0005 rule 10).** Creating, changing, pausing, resuming,
  reassigning and deleting a schedule are EP-3 Actions with `Target: Store`, named
  `reports.schedule.create | update | pause | resume | reassign | delete`. Each has an inline
  preview diff against the current version, the gate, step-up where the policy requires it, audit
  and **undo, which restores the previous version**. The Action runs inline in the request. The
  **external-recipient confirmation** ("Data leaves your organisation: <address>") is part of the
  Action preview, so the confirmation and the diff are one step and the confirmed addresses are in
  the audit event. **Not Actions** (system bookkeeping, ADR-0005 rule 10): report runs, exports
  and deliveries (DM-72, DM-84), and a pause the system itself makes under the owner-authority
  rule, which is audited as an event with its reason.

### 8.5 Permissions

Proposed registry IDs (X6) for `api-engineer` to bind as `x-permission`. Built-in role defaults
belong to the delegation spec; 2a requires only that the permissions exist and are enforced.

| Permission | Allows |
| --- | --- |
| `reports.run` | See the library and run reports within the runner's scope |
| `reports.export` | Export a run and download its files |
| `reports.schedule` | Create and manage the account's own schedules |
| `reports.schedule.manage_all` | See, pause and reassign any schedule |
| `reports.deliver.external` | Deliver to an address outside the allowed domains |

Report-category restriction per role (ADM-102) is not in 2a. At 2a a role either has `reports.run`
or does not.

### 8.6 Audit trail (our own; TM-TB15-T6)

One event per item, recording actor, report and version, scope summary, filters hash, row count and
digest, never values: report run; export created; export downloaded (including each delivery-link
download, with the downloading account); export expired or deleted; schedule created, changed,
paused, resumed, reassigned, deleted (written by the `reports.schedule.*` Actions, with the
confirmed external addresses); a system pause with its reason; run of a schedule (with owner scope
applied); delivery sent or failed, per recipient, including the run-time external-permission
failure.

## 9. Security and audit considerations

- **Directory privileges.** Reports read the inventory and, for USR-04 and PWD-03, call
  `ReadPerDC` under the connector's existing read rights. No new directory right is requested.
  No report writes to a directory.
- **Tier-0.** Reports may list Tier-0 objects (Domain Admins and similar), since `tier0` limits
  writes only (DM-35.I5). GRP-02 on a privileged group is the expected audit use.
- **Safe primitives.** Report SQL comes only from `store/reportsql` with registry identifiers and
  bound arguments (FF-SP4). Scope comes only from T-0094. Export bytes only from the P7 encoders.
  Attribute values are attacker-controlled (TM-X3: users edit their own profile fields), so the
  formula and HTML encoders apply to every cell.
- **Data leaving (TB15).** Exports and deliveries are audited with actor and row count (T6).
  External delivery needs its own permission (DM-73.I2). Caps and streaming bound resource use (T8).
  Secrets cannot reach an export (T3).
- **Abuse cases covered.** A technician who widens an owner's scope cannot make a schedule exceed
  the owner's scope (T2). An imported schedule (MIG-06) lands disabled with recipients shown
  (TM-TB18-T9). A per-DC report cannot be used to hammer DCs (read cap, daily floor). A sharing link
  carries no data. Row counts do not leak out-of-scope objects (post-trim counts).
- **`security-sensitive` tags.** T-0099, T-0103 and T-0104 already carry the tag. T-0100, T-0101 and
  T-0102 should carry it too, because T-0100 defines what data a report discloses and T-0101/2 are
  the data-leaving encoders. A note goes on each (§12).

## 10. Platform matrix

`✓` supported · `◐` partial, as stated · `✗` not at 2a, with the ticket. Profiles are `windows` and
`linux-oci` (ADR-0002). Reports are server-side and behave identically in both profiles (ADR-0002
rule 1). Exchange on-prem and Online, the end-user portal and the Windows, macOS and Linux logon
agents are `n/a` for every FR: reports have no behaviour on them at 2a.

**Platform facts that shape the reports.**
- Managed DCs are Windows Server 2016–2025 (ADR-0002). Domain functional level 2008 or later is
  expected for those DCs `[UNVERIFIED]`. `lastLogonTimestamp` needs domain functional level 2003 or
  later, and PSOs and `msDS-ResultantPSO` need 2008 or later
  ([MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad735d45-ba6a-42fc-a41c-e91ced8e72d9)).
  Where an input does not exist at a domain's level, the derived state shows "Unknown (input
  missing)", never a guess (§6.4).
- Windows Server 2016 through 2025 DCs: no documented change to the lockout, password-expiry or
  `lastLogonTimestamp` rules was found `[UNVERIFIED for 2025]`.
- Samba AD (the CI lab): replicated attributes and `ReadPerDC` are testable. Lockout expiry, PSO
  duration and `msDS-UserPasswordExpiryTimeComputed` are `[UNVERIFIED]` on Samba and need the
  Windows lab (`[LAB: Windows]`, v1-scope §8 Q5). The derivation itself is a pure function of
  stored inputs and is tested with table-driven inputs on any platform.

| FR | AD on-prem (WS2016–2025 DCs) | Entra cloud-only | Hybrid synced objects | Console | REST API | PowerShell module | `windows` | `linux-oci` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FR-01…FR-05 library | ✓ | ✗ → hybrid-slice ticket (§12) | ◐ AD side only, the Entra copy is not shown | ✓ | ✓ | ◐ follows the API, no cmdlet spec at 2a | ✓ | ✓ |
| FR-06…FR-09, FR-11…FR-15 run | ✓ | ✗ → same | ◐ AD side only | ✓ | ✓ | ◐ | ✓ | ✓ |
| FR-10 per-DC reads | ✓ | n/a (no DCs) | ◐ AD side only | ✓ | ✓ | ◐ | ✓ | ✓ over the same LDAP transport |
| FR-16…FR-22 export | ✓ | ✗ → same | ◐ | ✓ | ✓ | ◐ | ✓ | ✓ |
| FR-23…FR-29 schedule | ✓ | ✗ → same | ◐ | ✓ | ✓ | ◐ | ✓ | ✓ |
| FR-30…FR-32 permissions, API, states | ✓ | ✗ → same | ◐ | ✓ | ✓ | ◐ | ✓ | ✓ |

`windows` reaches GA only when T-0123–T-0126 land (m2-plan decision 9). Checkpoint 2a is demoed on
`linux-oci`. This spec adds no Windows-only behaviour, so nothing here lags on either profile.

## 11. Out of scope, and decisions made in this spec

| Item | Goes to | Why |
| --- | --- | --- |
| Report builder, LDAP-filter import, cloning shipped reports (ADM-097) | 2c (domain-model Q5) | Spec is separate |
| Act on results (ADM-098) | 2b | The report grid selects nothing at 2a |
| Compliance report sets (ADM-093) | Later E-012 slice | Needs the second slice first |
| Report from CSV (ADM-096) | Later E-012 slice | |
| Report-category delegation (ADM-102), dashboard widgets (ADM-103) | 2b / 2c grooming | |
| Entra and M365 reports (ADM-094) | Hybrid slice, 2c | No Entra rows in 2a datasets |
| Second slice of AD reports (§6.3) | Follow-up spec | |
| CSVDE, password-protected export, logo and serial number on exports (ADM-100) | P2 follow-up, before M2 exit | See below |
| Mail-body delivery, save to a path (ADM-101) | See below | |

**Decisions made here** (log entries; the CEO may veto):

1. **Minimum schedule interval is 1 hour**, not ME's minutes. A minute-level schedule to an
   external address is a mail-bomb primitive, and reports read synced inventory, so sub-hour runs
   add no information. This is a deliberate parity difference.
2. **No "save to a path" delivery.** A server writing to a UNC path coerces the service identity to
   an attacker-chosen host (TM-X3 describes the vector for `homeDirectory`). Exports are stored
   artefacts with an authenticated link. If a customer needs a file drop, it is a later ticket with
   a security review.
3. **No mail-body delivery at 2a.** It needs a body encoder over attacker-controlled cells and has
   a size ceiling. It goes after the encoders ship.
4. **PDF and HTML after the 2a demo.** The demo uses CSV and XLSX. Both ship before M2 exit.
5. **The in-app share link carries no data.** The URL of a report view re-runs under the opener's scope. This is distinct from a delivery link in a schedule (§8.4), which serves a stored artefact to one named recipient.
6. **Probable service accounts are hidden by default** (E2). ME shows everything.
7. **Inactive Users default to enabled accounts and 90 days**, unlike ME's 30 days with disabled
   accounts included.

## 12. Open questions, follow-ups and hand-offs

| # | Question | Owner | Blocks |
| --- | --- | --- | --- |
| Q1 | `[DISCOVERY]` Partner discovery has not returned. The 16-report slice, the 90-day default and the delivery set come from research. Re-weight on arrival | product-manager | Nothing now |
| Q2 | **Per-DC mechanism.** §6.5 states the required result, not the mechanism. Live read versus a stored per-DC dataset refreshed by a sweep, the unit of the read cap and the p95 are decided in the ADR T-0181 | solution-architect, T-0181 | USR-04 and PWD-03 in T-0099/T-0100. The other 14 reports do not wait |
| Q3 | **Where the allowed recipient domains list lives**, and the attachment size limit (T-0095 SMTP settings or the schedule) | backend-engineer | T-0104 |
| Q4 | Row cap and concurrency numbers (§8.3) calibrated on the scale tier | reporting-engineer, T-0116 | None, defaults apply |
| Q5 | *Withdrawn: ADR-0005 rule 10 rules that schedule writes are Actions (§8.4). The number is kept so other notes' references to Q6 stay valid* | n/a | n/a |
| Q6 | The staleness threshold and the per-NC "last successful sync pass" watermark (D6) | directory-engineer in T-0065 | FR-08 freshness labels |

No question here is directional: nothing needs the CEO.

Follow-ups filed from this spec (`backlog`, not scope creep): T-0172 (research), T-0173 (second slice), T-0174 (DM-16), T-0175 (ADM-100/101 remainders), T-0176 (Entra reports).
1. research · `market-analyst` — confirm ME semantics for Workstation Computers, Computers Trusted for
   Delegation, Managed/Unmanaged Computers and Groups, Users Not in Groups, Mail Enabled Contacts,
   Recent Logon Failures versus "Recently bad logged users", and ME's export password protection.
2. spec · `product-manager` — second slice of the AD report library (§6.3), including ADM-092.
3. spec · `ad-expert` — amend DM-16 inputs (D7) and add the lab rows for lockout, PSO and expiry.
4. build · `reporting-engineer` — ADM-100 and ADM-101 remainders: CSVDE, password-protected export,
   logo and serial number, mail-body delivery.
5. spec · `product-manager` — Entra object reports for the hybrid slice (ADM-094 basics).

Follow-ups filed by the architect review: T-0181 (per-DC read mechanism ADR) and T-0182 (derived dataset columns on EP-8).

Notes also go on T-0065, T-0091 (D6, D7), T-0100/T-0101/T-0102 (`security-sensitive`) and T-0095
(Q3).

## 13. Functional requirements

Each FR names a parity ID or `enhancement`. Others cite them as `reports-2a#FR-nn`.

**Library**

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-01 | The library MUST list the 16 reports of §6.2 in six categories, each with description, dataset and its freshness label. It MUST show only reports the user can run | ADM-083 |
| FR-02 | Library search and `/` search MUST match every ME name in §6.2 and open the report with that preset applied, showing "Also known as" | ADM-083 |
| FR-03 | Every shipped definition MUST be immutable. Changing one MUST publish a new version, and every run MUST record the version used | ADM-083, X7 |
| FR-04 | Opening a report MUST show results for its default preset without a Generate action | enhancement (E1 experience) |
| FR-05 | A definition MUST be an AST over one registered dataset. No report MAY accept a raw LDAP filter or any text executed as a query | DM-71.I3 |

**Run**

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-06 | The run MUST support scope by domain (multi-select, default all permitted), OU include/exclude, period presets and custom range, typed per-column filters and adding or removing registered columns | ADM-099 |
| FR-07 | Every run MUST apply the runner's scope inside the query. Counts and pages MUST be computed after trimming. A scope kind the 2a evaluator does not support MUST grant nothing | ADM-099, DM-71.I1 |
| FR-08 | Every run MUST store and show `as_of` and a freshness label per §8.2, and MUST NOT say "live" except for per-DC reads | enhancement (E1), DM-72.I1 |
| FR-09 | Locked-out, password-expired, password-expires-at and account-expired states MUST be computed at run time by the rules of §6.4, **as columns evaluated inside the compiled query (now and resolved policy bound as arguments), never a post-filter in application code** (T-0182), and MUST show "Unknown (input missing)" rather than infer | ADM-084, ADM-085 |
| FR-10 | USR-04 and PWD-03 MUST follow §6.5: per-DC coverage shown, partial coverage labelled a lower bound with no "never", a read cap that refuses before reading | ADM-084, ADM-085 |
| FR-11 | A run MUST be a job with the states of §8.1, visible progress and cancel, a typed failure reason and retry. A change of preset, filter, period, scope or columns MUST create a new run. Paging and sorting MUST read the same run | DM-72 |
| FR-12 | Paging, sorting and filtering MUST be server-side and total counts MUST not load every row | ADM-099 |
| FR-13 | The grid MUST offer sort, per-column filter, column chooser and row count. It MUST NOT offer a selection-based action at 2a | ADM-099 |
| FR-14 | USR-03 and PWD-01 MUST hide probable service accounts by default, show the count and reason, and never delete them from the data (§6.7) | enhancement (E2) |
| FR-15 | Effective membership MUST follow §6.6: primary group, cycles as findings, unresolved external principals, covered domains stated | ADM-086 |

**Export**

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-16 | Export MUST offer CSV and XLSX at the 2a demo, and PDF and HTML before M2 exit. It MUST offer only formats that exist | ADM-100 |
| FR-17 | An export MUST serialise the stored result of the run on screen: the on-screen columns, the filters applied, all rows up to the cap, and carry the About block of §8.3 (not in CSV) with the digest defined by the canonical form of §8.3 and the run's `as_of` | ADM-100, enhancement (E3) |
| FR-18 | Caps of §8.3 MUST refuse and explain. They MUST NEVER truncate silently | TM-TB15-T8 |
| FR-19 | All export bytes MUST come from the P7 encoders. A raw writer MUST fail CI | TM-TB15-T1 |
| FR-20 | Exports MUST run as asynchronous jobs, be stored tenant-prefixed with expiry, download only through authenticated requests, return 410 when expired and be deletable early | DM-72.I3 |
| FR-21 | No secret attribute MUST be exportable | TM-TB15-T3 |
| FR-22 | Each run, export, download and delivery MUST be audited with actor and row count, never values | TM-TB15-T6 |

**Schedule**

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-23 | A schedule MUST be creatable from the open report with presets, a recurrence per §8.4 (1-hour floor), an IANA time zone and DST rules | ADM-101 |
| FR-24 | Delivery MUST support attachment, ZIP and (for accounts) link, formats per recipient, and notify-only-if-data. A link MUST be downloadable only by the named recipient account holding `reports.export`, MUST serve the owner-scope artefact exactly as an attachment would, and every download MUST be audited | ADM-101 |
| FR-25 | Each run MUST use the owner's scope and permissions at that moment. A disabled or deleted owner, or one who lost `reports.run`, `reports.export` or `reports.schedule`, MUST pause the schedule with the reason. At each fire every external recipient MUST be re-evaluated against the current allowed domains and the owner's current `reports.deliver.external`, and a failing recipient MUST fail alone with the reason | DM-73.I1 |
| FR-26 | An external recipient MUST need `reports.deliver.external` and a confirmation that is part of the Action preview. The sheet MUST state that recipients receive what the owner can see | DM-73.I2, TM-TB15-T2 |
| FR-27 | Each recipient MUST have its own delivery state shown on the schedule, and failures MUST notify the owner after retries | enhancement (E4) |
| FR-28 | Per-DC reports MUST NOT run more often than daily. Missed runs after downtime MUST run once | DM-44.I2 |
| FR-29 | Schedule create, update, pause, resume, reassign and delete MUST be EP-3 Actions `reports.schedule.*` with preview diff, gate, step-up, audit and undo that restores the previous version (ADR-0005 rule 10). Reassignment MUST pause the schedule. Runs and deliveries MUST NOT be Actions | DM-73, ADR-0005 rule 10 |

**Permissions, API, states**

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-30 | The permissions of §8.5 MUST exist and be enforced on every API operation | ADM-102 (partial) |
| FR-31 | Every behaviour above MUST be an OpenAPI operation first, with `x-permission` (ADR-0004), and the console MUST use only the generated client | ADR-0004 |
| FR-32 | Every screen MUST show the empty, error, stale and loading states of §5, with no fake data and no control that does nothing | house rule 6 |

## 14. Acceptance criteria

Evidence names are the test or artefact the `qa-verifier` produces. "Lab" is the CI AD lab (Samba);
`[LAB: Windows]` criteria are not met until run on a Windows DC lab and are reported separately
until then. The derivation criteria also run as table-driven tests that need no DC.

```
AC-01 (T-0067 acceptance 1)
Given the shipped library
When an admin lists the reports
Then there are 16, each with an ID, category and dataset, and every ME name in §6.2 resolves to
  its report and preset, with default columns and default filters equal to the §6.2 row
Evidence: reports_library_matches_spec test comparing the definitions to this table; API output

AC-02
Given a search for "Recently Logged on Users"
When the admin presses Enter
Then Logon activity opens with that preset applied and the page shows "Also known as"
Evidence: UI recording; test reports_search_by_me_name

AC-03
Given a shipped definition
When any caller tries to edit it
Then the change is refused, and only a new shipped version replaces it
Evidence: API test; the run record shows definition_version (FR-03)

AC-04
Given any report
When it opens
Then rows are on screen with no Generate click, and the interaction count to reach them from
  `/` is 3 (benchmark T20 steps 1-3)
Evidence: ux-review trace; screenshot

AC-05
Given a request carrying an LDAP filter string in any report parameter
When it is submitted
Then it is rejected as an unknown parameter and no query runs
Evidence: API negative test (FR-05)

AC-06
Given a runner scoped to one OU in a lab with objects in other OUs and domains
When they run Users, Groups, Computers and OU reports
Then rows, totals and "checked n objects" exclude everything outside the OU
Evidence: integration test comparing counts with a direct LDAP query of that OU

AC-07
Given a runner whose role uses a group_members or Entra scope kind
When they run any report
Then no rows are returned, and the empty state names the unsupported scope kind
Evidence: test reports_unsupported_scope_fails_closed

AC-08
Given a completed run
When it is fetched through the API and the UI
Then it carries as_of and the freshness label, equal to the oldest covered NC watermark
Evidence: API test; header screenshot

AC-09
Given a quiet domain with no changes for 24 hours but successful sync passes
When a report runs
Then it shows "Synced <time of last pass>", not "Stale"
Evidence: test with a seeded SyncCursor (requirement D6)

AC-10
Given a covered NC in resync_required or paused
When a report runs
Then it runs, shows "Stale" with age and cause, and an export and a schedule delivery carry the label
Evidence: test; export About block

AC-11
Given a connection that never completed a first sync
When a report runs
Then the connection is listed as skipped, and rows for others are returned
Evidence: test

AC-12 (T-0067 acceptance 2)
Given a user whose lockoutTime is non-zero and whose lockout duration has elapsed
When Locked-out Users runs
Then the user is absent, with no write to the directory in between; and a user inside the
  duration is present with "Lockout ends" computed from the effective duration
Evidence: table-driven derivation test (inputs: lockoutTime, duration, now); lab run on Samba
  for the arithmetic; [LAB: Windows] comparison to msDS-User-Account-Control-Computed

AC-13 (T-0067 acceptance 2)
Given the password-state table of §6.4
When each row's inputs are supplied (never-expires flag with pwdLastSet 0, smartcard-required,
  pwdLastSet 0, never policy, expired, soon, a PSO user)
Then each shows exactly the state of its row, "must change at next logon" is never shown as
  "expired", and a PSO user with a shorter age expires earlier than a default-policy user
Evidence: table-driven test with one case per row; [LAB: Windows] ground truth against
  msDS-UserPasswordExpiryTimeComputed

AC-14 (T-0067 acceptance 2)
Given a PSO or its group membership changes with no write to the user object
When Password status runs next
Then the user's state reflects the new effective policy
Evidence: lab test that edits the PSO only; [LAB: Windows] for the PSO precedence

AC-15
Given a computed input is missing (PSO unreadable, lockoutTime not read)
When the report runs
Then the state is "Unknown (input missing)" with the reason, never "not locked" or "not expired"
Evidence: fault-injection test

AC-16
Given a domain whose msDS-LogonTimeSyncInterval is 0
When Logon activity runs for it
Then that domain is disabled with a message, and a threshold under 30 days is not offered
Evidence: test; UI screenshot

AC-17 (E2)
Given a lab with 6 users with a servicePrincipalName and 1 plain user inactive for 90 days
When Inactive Users opens
Then the plain user is listed and "6 probable service accounts hidden" shows. Choosing Show lists each
  of the six with the reason "servicePrincipalName set", and benchmark T18 step 9 needs 0 unticks
Evidence: lab test; ux-review trace

AC-18
Given a flagged account that is a false positive
When the admin clicks include
Then the row appears, no data is changed, and the signal set is unchanged
Evidence: UI test

AC-19
Given a lab with a user whose primary group is not Domain Users and a group whose only members are primary-group users
When Users Not in Groups and Groups Without Members run
Then the first user appears with its primary group named, and the group is not reported as empty
Evidence: lab test against LDAP ground truth

AC-20 (E3)
Given a group nested three levels deep with a cycle, a foreign security principal and a disabled member
When Detailed Group Members runs
Then every effective member appears once with its Via path, the cycle is listed as a finding, the principal reads
  "External principal (unresolved)", the disabled member is flagged, and the covered domains are stated
Evidence: lab test; row-by-row comparison to a tokenGroups oracle

AC-21
Given groups with 1,501 and with 6,000 direct members
When Group Members and Detailed Group Members run
Then member counts equal the lab's LDAP ground truth and the first page appears within the §5 budget
Evidence: scale-tier test with measured times

AC-22
Given a lab of 100,000 users
When Users runs with the default preset
Then the first 50 rows and the count return within the §5 budget, with server-side paging, sorting and filtering
Evidence: T-0116 benchmark output

AC-23
Given a user report on the lab
When it runs
Then its rows equal an LDAP ground-truth query for the same preset
Evidence: comparison test per report (T-0099, T-0100)

AC-24 (T-0067 acceptance 3; TM-TB15-T8)
Given an export whose rows exceed the cap for its format (CSV above 1,000,000, XLSX above 1,000,000, PDF above 5,000, HTML above 20,000)
When the admin exports
Then the export is refused with the count, the cap and the options, and no file, partial or
  truncated, is created
Evidence: test per format using lowered caps

AC-25 (T-0067 acceptance 3)
Given an export at exactly the cap
When it runs
Then it succeeds with all rows, streamed, and the server's memory stays below the bound set by T-0101
Evidence: streaming test with memory sample

AC-26
Given attribute values that start with =, +, -, @, a tab, CR, LF or the full-width forms
When the report is exported to CSV and XLSX
Then the file opens in Excel or LibreOffice without evaluating a formula
Evidence: P7 corpus test (FF-SP11 oracle)

AC-27 (E3)
Given a nested-membership view exported to XLSX
When the file is opened
Then the first sheet states the report, scope, filters, freshness, generated by and at, row count and digest, every row has Via, and the digest equals the SHA-256 of the §8.3 canonical form recomputed from the run's rows (AC-50)
Evidence: test recomputing the digest

AC-28
Given an export
When it is created and downloaded
Then one audit event records each with actor, format, row count and digest; and an expired file returns 410
Evidence: audit query; API test

AC-29
Given a secret attribute name (a BitLocker or LAPS value)
When a column or filter names it
Then the request is refused as an unregistered column
Evidence: unit test (D8, FR-21)

AC-30 (T-0067 acceptance 3; DM-73.I1)
Given a schedule whose owner's scope shrank from two OUs to one
When the next run fires
Then the output has only the smaller scope, the run record shows the scope applied, and no cached scope is used
Evidence: test T-0104 AC1

AC-31 (DM-73.I1)
Given a schedule whose owner is disabled
When the next run is due
Then the schedule is paused with the reason, tenant owners are notified, and nothing is sent
Evidence: test

AC-32
Given an owner who lost reports.run
When the next run is due
Then the schedule pauses with the reason
Evidence: test

AC-33 (DM-73.I2)
Given a recipient address outside the allowed domains and an owner without reports.deliver.external
When the owner saves the schedule
Then the reports.schedule.create Action is refused at preview; with the permission, the preview shows
  the confirmation "Data leaves your organisation: <address>" in the same diff, and an empty
  allowed-domains list makes every address external
Evidence: API and UI tests

AC-34
Given a schedule reassigned to another owner
When the reassignment is saved
Then the schedule is paused until the new owner resumes it after seeing the recipients
Evidence: test

AC-35
Given Notify only if data and a run with zero rows
When the schedule fires
Then the run is recorded, nothing is sent, and the list shows "ran, nothing to send"
Evidence: mail-catcher test

AC-36
Given a schedule with three recipients and one delivery failing
When the run completes
Then each recipient shows its own state, the failure retries and then notifies the owner
Evidence: mail-catcher test with an induced failure

AC-37
Given a monthly schedule at 08:00 in a zone with a DST change, and a server down across a due time
When the next fire happens
Then DST rules of §8.4 hold and the missed run executes once
Evidence: clock-injected test (DM-44.I1/I2)

AC-38
Given a per-DC report and a schedule of hourly
When the owner saves
Then it is refused with "no more often than daily"
Evidence: API test

AC-39 (§6.5)
Given USR-04 on a lab with 3 DCs and one logon seeded on a DC other than the first
When it runs with all DCs answering
Then Real last logon equals the maximum over the DCs, names the DC, and coverage reads COMPLETE
Evidence: lab test with seeded per-DC values

AC-40 (§6.5)
Given one DC unreachable
When USR-04 runs
Then coverage reads "2 of 3 DCs", the column reads "at least", a user with no logon on the answered DCs
  reads "Not confirmed" and never "never", and the unreachable DC is named with its error
Evidence: fault-injection test

AC-41 (§6.5)
Given a scope whose estimate exceeds the read cap
When USR-04 runs
Then it refuses before reading any DC, stating the estimate, the cap and the options
Evidence: test with a lowered cap; DC read counter shows zero

AC-42
Given a role without reports.run
When the user opens the console or calls the API
Then no report entry shows, search finds no reports, and every report operation returns forbidden
Evidence: API and UI tests for each operation and permission of §8.5

AC-43
Given the run, export and schedule operations
When the OpenAPI contract is generated
Then each has exactly one x-permission and the console calls them through the generated client
Evidence: fitness-api output (ADR-0004)

AC-44
Given each screen of Flow A
When it is shown empty, loading, stale, failed and at 100,000 rows
Then each state is real and every control does something
Evidence: qa-verifier click-through with screenshots

AC-45 (ADR-0005 rule 10)
Given a schedule is created, changed, paused, resumed, reassigned and deleted
When each is performed
Then each is a reports.schedule.* Action with a preview diff against the current version, an audit
  event and an undo that restores the previous version; and a report run or a delivery appears as
  bookkeeping, not as an Action
Evidence: operation-kernel test per Action; fitness O3 output

AC-46 (DM-73.I1)
Given a schedule with an external recipient, saved when the owner held reports.deliver.external and
  the address was external
When the owner loses reports.deliver.external, and separately when an admin adds the address's
  domain to the allowed list
Then at the next fire the first case fails that recipient alone with the reason while the other
  recipients are delivered and the schedule stays active; in the second case the address is
  delivered with no external check. Separately, an owner who loses reports.export pauses the schedule
Evidence: mail-catcher test with permission and allowed-domain changes between fires

AC-47 (TM-TB15-T2 residual)
Given a schedule owned by an account scoped to two OUs, a link recipient account scoped to one OU
  holding reports.export, a second account without reports.export, and a third account that is not
  a recipient
When each opens the delivery link
Then the named recipient downloads the owner-scope artefact, whose digest equals the one in the run
  record; the other two are refused; a signed-out request is refused; each attempt is audited
Evidence: API tests with digest comparison; audit query

AC-48 (FR-11, FR-17)
Given a report on screen with a run R
When the admin pages and sorts, then exports, then changes a filter, then exports again
Then paging and sorting return rows of R with unchanged as_of, the first export's rows and digest
  equal R's stored result, and the filter change creates a new run R2 whose as_of, count and
  export are its own
Evidence: API test comparing run ids, as_of, row sets and digests

AC-49 (FR-09, T-0182)
Given a lab with 40 users of whom 37 are currently locked out by the §6.4 rule and more than one page
  of other users
When Locked-out Users is filtered, sorted by "Lockout ends" and paged
Then the total is 37, pages contain only locked-out users in the sorted order, and the compiled
  query contains the lockout predicate with now and the policy bound as arguments, with no
  application-side filtering
Evidence: API test; query-plan or compiled-SQL assertion; table-driven cases

AC-50 (§8.3 canonical form)
Given a run and its exported CSV, XLSX and (once shipped) PDF and HTML files, and a test that
  recomputes the digest from the run's rows through the API using the canonical form
When the digests are compared
Then they are equal for every format, they change when any value, the column order or the row order
  changes, and a null differs from an empty string
Evidence: platform/export canonical-form test vectors (T-0101)

```

### Traceability: which FR each build ticket consumes

| Ticket | FRs |
| --- | --- |
| T-0075 | FR-05, FR-07, FR-12 |
| T-0182 | FR-09 (derived columns evaluated in the query), AC-49 |
| T-0099 | FR-04, FR-06–FR-14 (USR reports first), AC-48, AC-49 |
| T-0100 | FR-01, FR-02, FR-09, FR-10, FR-14, FR-15 (remaining reports) |
| T-0101, T-0102 | FR-16, FR-17, FR-19, FR-21, canonical form and AC-50 |
| T-0103 | FR-17, FR-18, FR-20–FR-22 |
| T-0104 | FR-23–FR-29 (AC-30–AC-38, AC-45–AC-47) |
| T-0106, T-0114, T-0115 | §5, FR-01–FR-04, FR-32 |
| T-0116 | AC-21, AC-22, AC-23, AC-39 |

## Sources

Inline above. ME pages read on 2026-10-02:
[report list](https://www.manageengine.com/products/ad-manager/active-directory-reports-list.html),
[user reports](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html),
[scheduled reports](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-scheduled-reports.html).
The AD semantics come from an `ad-expert` consult for this ticket, with the Microsoft Learn links
cited in §6.4–§6.6 and §10. Items the consult could not source carry `[UNVERIFIED]`.

## Changelog

- 2026-10-02 · created (T-0067)
- 2026-10-02 · revised after the solution-architect review: schedule writes are `reports.schedule.*` Actions (ADR-0005 rule 10, §8.4, FR-29, Q5 dropped); run-time checks of every permission and external recipient (FR-25); one delivery-link rule (FR-24); run and snapshot semantics (§8.1, FR-11, FR-17); derived states evaluated in the query (§6.4, FR-09, T-0182); canonical digest form (§8.3); per-DC wording mechanism-neutral (§6.5, Q2 to T-0181). Added AC-45 to AC-50
