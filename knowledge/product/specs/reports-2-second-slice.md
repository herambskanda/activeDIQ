---
title: "Spec: AD report library, second slice (reports-2a §6.3 'Not at 2a', including ADM-092)"
date: 2026-10-31
updated: 2026-10-31
status: draft
owner: heramb
author: product-manager
ticket: T-1015
epic: E-002
milestone: M2a
parity: [ADM-084, ADM-085, ADM-086, ADM-087, ADM-089, ADM-092]
scope: proposed
sources_last_checked: 2026-10-31
---

# Spec: AD report library, second slice

> An admin finds every ManageEngine report they run on a routine (what changed or was deleted, who
> cannot change a password, which accounts carry odd settings, what the password and lockout
> policy is, which DCs are not replicating) by its ManageEngine name, with results on screen, with
> each unknown and each limit of the directory stated on the report instead of being guessed.

This is the follow-up 2 of [reports-2a.md](reports-2a.md) §12. It specifies the rows of reports-2a
§6.3 ("ME names not in 2a, and where each goes"). It inherits every rule of reports-2a that it does
not change: library rules §6.1, derived states §6.4, per-DC rules §6.5, run, scope, freshness and
export §8, security §9, FR-01…FR-32 and AC-01…AC-50. It adds reports, datasets and acceptance
criteria, and amends exactly three rules, listed in §9. It is reviewed by `solution-architect`.

Directory behaviour in this spec comes from an `ad-expert` consult on 2026-10-31 (no lab run) and
from the Microsoft pages cited. `[UNVERIFIED]` marks what the consult could not source and
`[LAB: Windows]` what only a Windows DC lab can settle. ManageEngine (ME) behaviour comes from ME's
own help pages read on 2026-10-31 and from the
[ADMP research](../../business/market-research/manageengine-admanager-plus.md) §3.K; the research
ticket T-1014 has not landed, so every ME meaning below that is not in the research is tagged
`[ME-HELP]` (stated by ME's page, not yet in the research) or `[UNVERIFIED]`.

## 1. Problem and users

Reports-2a ships 16 reports that answer 54 ME names. The rest of ME's AD library (35 user, 8
password, 16 group, 18 computer, 13 contact and OU, and 5 "other" reports) is what an ADMP
customer meets in their first week on activeDIQ. A name that is missing is a reason to keep ADMP
running beside us. This slice closes the AD side of ADM-084 to ADM-089 and ADM-092 except for the
rows that §2 keeps out with a reason.

| Persona | Job | Why the 2a slice does not do it |
| --- | --- | --- |
| AD admin | When something broke overnight, I want what changed or was deleted in the last days, to find the cause or restore the object | "Recently Modified/Deleted" is in 5 object kinds and not in 2a |
| Security/SOC analyst | When I review account hygiene, I want who cannot change a password, who is a smart-card account, who may dial in | These need attributes or the security descriptor outside the 2a set |
| Compliance auditor | When a control asks "what is the password and lockout policy", I want it on one page with the fine-grained policies and what they apply to | ADM-092 Password Policy and Account Lockout Policy are not in 2a |
| AD admin / infrastructure | When logons behave oddly, I want to know which DCs are replicating | DC Replication Status is not in 2a |
| Help-desk technician | I want the same reports within my delegated OU only | Inherited scope rules, reports-2a §8.1 |

Frequency and source: report routines are the daily and monthly rhythm of an ADMP customer
([ADMP research §7a](../../business/market-research/manageengine-admanager-plus.md)); report UX is
the #2 complaint theme, about 17 reviews
([customer voice X2](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
No partner discovery has returned, so the choice of which lower-use reports to keep is
`[DISCOVERY]`: re-weight when it arrives (reports-2a Q1).

## 2. Disposition of every row of reports-2a §6.3

"Specced" means the report has an ID, a batch and a definition in §4 to §7. "Out" means kept out of
this slice with a reason and an unblocker. Every ME name below comes from ME's help pages listed in
§3.

| §6.3 row | Disposition | Where |
| --- | --- | --- |
| Recently Modified / Recently Deleted (users, groups, computers, contacts, OUs) | **Specced.** 9 ME names (ME has no Recently Deleted OUs), plus 1 non-ME preset | §4.1, batch 5 |
| Users with Cannot Change Password | **Specced** with the security-descriptor truth, not ME's flag | §4.2, batch 4 |
| Bitlocker Recovery Keys; Bitlocker Enabled / Disabled Computers | **Out.** Recovery values are secrets and never stored (X4, TM-TB15-T3). Enabled/Disabled in ME is derived from keys held in AD ("computers that do not have BitLocker keys" `[ME-HELP]`), which says escrowed, not enabled, and needs the `msFVE` child objects, not in the synced set. Unblocker: 2b decision on `ReadSecret` and an escrow-only sync | §8 |
| Photo Based, Dial-in Allow/Deny, Users with/without Logon Script, Skype/Lync Enabled/Disabled, Smart Card Enabled, Logon Hour Based | **Specced** | §5.1 to §5.4, batch 6 |
| Terminal Services (2) | **Out.** The data is the legacy `userParameters` blob; decoding a shared binary blob in a product that sits in a domain needs a hardened, fuzzed decoder and its own spec. The `msTS*` attributes are rarely populated `[UNVERIFIED]`. Unblocker: follow-up spec (§10 F3) | §8 |
| Users with Empty / Duplicate Attributes | **Specced**, over registered columns only | §5.5, batch 6 |
| All Managers, Manager Based Users | **Specced** | §6.1, batch 7 |
| Users in More than One Group | **Specced** | §6.2, batch 7 |
| Users Only Members of Domain Users Group | **Specced** | §6.3, batch 7 |
| Computers with Duplicate Attributes | **Specced** | §6.4, batch 7 |
| Managed Computers, Unmanaged Computers | **Specced, gated.** ME's page defines them (`managedBy` set or not) `[ME-HELP]`, but the research does not carry it. Built only if T-1014 confirms; otherwise out and the count drops by 2 | §6.5, batch 9 |
| GPO Linked OUs, GPO Blocked Inheritance OUs (ME titles it "GPO Inheritance Blocked OU") | **Out.** Needs the GPO link model (DM-23, E-008), not report work. Unblocker: the E-008 spec | §8 |
| Password Policy, Account Lockout Policy (ADM-092) | **Specced** | §7.1, batch 8 |
| Printer Reports (ADM-092) | **Specced** as "Published printers" | §7.2, batch 10 |
| DC Replication Status (ADM-092) | **Specced** (read-only, per DC, with a stated right needed) | §7.3, batch 10 |
| Lingering Objects (ADM-092) | **Out.** LDAP cannot prove a lingering object; authoritative detection is a DRSUAPI call (`DsReplicaVerifyObjects`, advisory mode) on Windows, and ME's version can delete (a Tier-0 write). The slice ships only a clearly named *risk indicator* inside SYS-03 and no detection claim. Unblocker: follow-up spec (§10 F2) | §7.3, §8 |
| Exchange, GPO, NTFS/Permissions, M365, Google Workspace families (ADM-088, 090, 091, 094, 095) | **Out.** Matrix priorities P4, P2, P2, P4, P4 ([matrix](../../business/competitive-analysis/feature-parity-matrix.md)) | their milestones |

**Counts.** This slice adds **18 reports** (17 firm, CMP-05 gated) answering **32 ME names** (30
firm). With the 16 reports and 54 names of reports-2a the library reaches 34 reports (33 firm)
and 86 names (84 firm). Names kept out: Terminal Services 2, Lingering Objects 1, BitLocker 3, GPO
OUs 2. How the PRD's "60+ reports" is counted (definitions, or definitions plus presets) is the
`project-manager`'s reading; both counts are given so it can be stated honestly.

## 3. ManageEngine parity baseline

| Parity ID | ME (edition) | This slice | Sources |
| --- | --- | --- | --- |
| ADM-084 | User reports (35) (Std+Pro) | USR-06…USR-09, USR-11…USR-13: 16 ME names (USR-10 is reserved, unassigned: Terminal Services is out) | [user reports help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html) |
| ADM-085 | Password reports (8) (Std+Pro) | PWD-04: 1 name | [password reports help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-password-reports.html) |
| ADM-086 | Group reports (16) (Std+Pro) | GRP-05, GRP-06: 3 names | [group reports help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-group-reports.html) |
| ADM-087 | Computer reports (18) (Std+Pro) | CMP-03…CMP-05: 5 names (2 gated) | [computer reports help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-computer-reports.html) |
| ADM-089 | Contact and OU reports (13) (Std+Pro) | CTC-02, OU-02: 3 names | [contact and OU help](https://www.manageengine.com/products/ad-manager/help/reports/how-to-get-active-directory-contact-and-ou-report.html) |
| ADM-092 | Other reports (5) (Std+Pro) | SYS-01, SYS-02, SYS-03: 4 of 5 names; Lingering Objects out | [other reports help](https://www.manageengine.com/products/ad-manager/help/reports/active-directory-other-reports.html), matrix row ADM-092 (P1, parity) |

All pages read 2026-10-31. Per-report name counts are in §4 to §7 and add to 32 (16 + 1 + 3 + 5 + 3
+ 4 across the rows above). No new parity IDs are needed: every row maps to an ID in the matrix.
Parity differences chosen on purpose are in §9.

**Report IDs and batches** (batch numbers from the T-1091 grooming tickets; `project-manager`
re-cuts if the plan differs):

| Batch | Reports | ME names | Ticket |
| --- | --- | --- | --- |
| 4 | PWD-04 | 1 | T-1107 |
| 5 | USR-06, GRP-05, CMP-03, CTC-02, OU-02 | 9 | T-1110 |
| 6 | USR-07, USR-08, USR-09, USR-11 | 11 | T-1112 |
| 7 | USR-12, USR-13, GRP-06, CMP-04 | 5 | T-1113 |
| 8 | SYS-01 | 2 | T-1114 |
| 9 | CMP-05 (gated on T-1014) | 2 | T-1115 |
| 10 | SYS-02, SYS-03 | 2 | to be filed by T-1118 |

## 4. Reports that depend on new data: change history and security descriptors

### 4.1 Recently Modified and Recently Deleted (batch 5)

Five reports, one per object kind, each with a Modified and (except OUs) a Deleted preset. They run
over a new dataset `inventory.object_changes` (D10, §10), built from the observation history
(DM-18), not from `whenChanged`, which is per DC and not replicated
([whenChanged](https://learn.microsoft.com/en-us/windows/win32/adschema/a-whenchanged)).

| ID | Report | ME names (presets) | Dataset |
| --- | --- | --- | --- |
| USR-06 | User changes | Recently Modified Users · Recently Deleted Users | `inventory.object_changes` (kind user, inetOrgPerson) |
| GRP-05 | Group changes | Recently Modified Groups · Recently Deleted Groups | same (kind group) |
| CMP-03 | Computer changes | Recently Modified Computers · Recently Deleted Computers | same (kind computer) |
| CTC-02 | Contact changes | Recently Modified Contacts · Recently Deleted Contacts | same (kind contact) |
| OU-02 | OU changes | Recently Modified OUs · *Recently Deleted OUs (not an ME name; ME's page has none `[ME-HELP]`)* | same (kind OU) |

**ME baseline.** ME: Recently Modified lists objects "whose attributes were modified within a
particular time period"; Recently Deleted lists objects deleted in a time span, "limited by AD's
deleted-object retention period" `[ME-HELP]`. For computers ME's page adds "the deleting account".
How ME decides "modified" (the `whenChanged` of one DC, or something else) is `[UNVERIFIED]`.

**Default columns (Modified):** Name, Logon name (users and computers), Domain, OU path, Change
(created / edited / moved / renamed / membership changed), Attributes changed (names only),
Changed at, Basis, Observed at.
**Default columns (Deleted):** Name, Logon name, Domain, Last known OU path, Deleted at, Basis,
Observed at, State, Restorable until.
**Default filters:** period last 7 days (presets 1, 7, 30, 90, 180, 365 plus custom); Modified
excludes the noise set below; Deleted lists `state` in deleted, recycled or purged.

**Rules.**
1. **Definition of "changed at".** The latest originating time of a recorded, non-noise change
   (DM-18 `origin`, which comes from `msDS-ReplAttributeMetaData`, replicated and independent of the
   DC). Where `origin` is null the value is the time activeDIQ observed the change. Column *Basis*
   says which ("DC time, originating" or "observed"). Observed time is always also shown (DM-18.I2:
   two changes between two observations show as one, and the report says so in its header).
2. **Noise is hidden by default, with its count and a switch.** The header reads "3,412 automatic
   updates hidden · Show". The hidden set, from the consult: logon and bad-password state
   (`lastLogonTimestamp`, `lastLogon`, `logonCount`, `badPwdCount`, `badPasswordTime`); lockout and
   housekeeping (`lockoutTime`, `adminCount`, `dSCorePropagationData`, a security descriptor
   rewritten only by SDProp or inheritance); computer-driven updates (operating system fields,
   `dNSHostName`, `servicePrincipalName`, `msDS-SupportedEncryptionTypes`, `msDS-KeyVersionNumber`,
   the machine password). **Password changes are not noise and not an edit:** they appear as change
   kind "credential event" (their own filter chip, off by default on the Modified presets, on in
   the "Include credential events" switch), never with a value. The noise set belongs to the
   definition version (X7). `[UNVERIFIED]` for the `msDS-LastSuccessful*`/`msDS-LastFailed*` family.
3. **Attribute names, never values.** The report shows which attributes changed, not old or new
   values (DM-18.I4, I6: personal values are erasable, secrets are never recorded). Value diffs
   are a later enhancement.
4. **Groups.** A membership change appears on the group as kind "membership changed" with "Members
   added n / removed m" for the period. A user whose group membership changed is not "modified"
   (the change is on the group's `member` link).
5. **History starts when we started watching.** The header states "Change history starts <first
   sync of each covered domain>. Earlier changes are not listed". To avoid a day-one report that is
   empty where ME's is not, a period that begins before the history does includes objects whose
   inventory `when_changed` falls in the uncovered part of the period, with Basis "whenChanged read
   from <DC> (includes automatic updates)". This is a decision, logged in §9.
6. **No actor.** DM-18.I3: v1 never attributes a native change to a person. The directory does not
   hold who deleted or edited an object; that needs Security events 4726, 4743, 4730, 5141 on the
   originating DC (consult). The reports carry no "Changed by" column and the header says why.
   ME's computer page promises "the deleting account" `[ME-HELP]`; that parity gap closes with the
   M3 DC event collectors (reports-2a §6.3 pattern: stated, not hidden). For changes made through
   activeDIQ itself the actor *is* known (DM-18 `source: operation`) and is shown.
7. **Deleted objects.** Read with the show-deleted control (`1.2.840.113556.1.4.417`) by sync
   (DM-19, T-0018). With the Recycle Bin on, the object keeps its attributes while `isDeleted`; once
   `isRecycled` it keeps few ([consult], [Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin));
   with it off, only attributes preserved on delete survive. So Name, Logon name and Last known
   OU path may be blank on a tombstone; a blank is shown as "Not retained by AD", never as empty.
   *State* is "Deleted (restorable)", "Recycled (cannot be restored)" or "Purged from the
   directory (history only)"; *Restorable until* is the deleted time plus the domain's
   `msDS-deletedObjectLifetime` (falls back to `tombstoneLifetime`, default 180 days on forests
   created from Server 2003 SP1 [tombstoneLifetime](https://learn.microsoft.com/en-us/windows/win32/adschema/a-tombstonelifetime));
   the column says "up to". The list keeps purged objects while our history does (ME is limited by
   AD's retention).
8. **Scope.** A deleted object is in the runner's scope only if its stored last-known ancestry is
   in scope. Unknown ancestry grants nothing and is never counted (reports-2a §8.1 fail closed). The
   2a rule that deleted and purged objects appear in no report (§6.1 rule 6) is lifted for the
   Deleted presets only; no other report lists them.
9. **Restore is not here.** The grid selects nothing (FR-13). Restore from this list is 2b
   (ADM-098, ADM-150).

### 4.2 Users with Cannot Change Password (batch 4, `security-sensitive`)

| ID | Report | ME names | Dataset | Default columns | Default filters |
| --- | --- | --- | --- | --- | --- |
| PWD-04 | Password change blocked | Users with Cannot Change Password (ME's page title: "Users who cannot change their password Report") | `inventory.users` | Name, Logon name, Domain, OU path, Password change right, Status, Password state, Probable service account, Descriptor as of | Preset: right is "Blocked" or "Blocked (one deny ACE only)". Probable service accounts shown (they are the usual holders; E2 hides only on expiry reports) |

**ME baseline and the discrepancy.** ME's page says the report queries the `userAccountControl`
flag "Password Cannot Change" `[ME-HELP]`. Active Directory does not honour that bit: the right is
an access-control matter, and Microsoft says it cannot be set through that attribute
([flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)).
The truth is two non-inherited deny ACEs on the user, object type
`ab721a53-1e2f-11d0-9819-00aa0040529b` (User-Change-Password) for trustees Everyone (`S-1-1-0`)
and SELF (`S-1-5-10`), which is what the AD tools write
([ADSI](https://learn.microsoft.com/en-us/windows/win32/adsi/reading-user-cannot-change-password-ldap-provider)).
The two can disagree whenever a script set one without the other, so **this report can differ
from ME's by design.** The comparison belongs to the ADMP check (follow-up F1, T-1116/T-1117 pattern).

**Rules.**
1. State of *Password change right* (stored by the sync from the security-descriptor read path,
   T-1019, T-1106; **no descriptor is read at run time**):

   | Value | Meaning |
   | --- | --- |
   | Blocked | Both deny ACEs are present |
   | Blocked (one deny ACE only) | One of the two is present. The user still cannot change the password, because the user matches Everyone and SELF; the AD tools would show the box unticked |
   | No deny ACE | Neither explicit deny ACE is present. The label never says "can change": inherited denies or other ACEs are not evaluated at this slice |
   | Not confirmed | The descriptor was unreadable, malformed or not yet read. Counted in the header, never listed as a match, never shown as "No deny ACE" |

   This **amends the T-1019/T-1106 wording** (a boolean "true only when both ACEs are present"):
   the decoder returns this four-valued typed state, not a boolean (§10 handoff note).
2. Scope: user accounts (`sAMAccountType` users and inetOrgPerson). Computer accounts are not
   listed `[UNVERIFIED]` that the right is irrelevant for them.
3. Reset Password is a different right (`00299570-246d-11d0-a768-00aa006e0529`), which admins keep;
   the report is not about it.
4. Full effective-right evaluation (token groups, inheritance order, allow ACEs) is not in this
   slice; the label "No deny ACE" is its honest stand-in.
5. Freshness: the column carries "Descriptor as of" (the sync observation). An ACL edit on a user is
   a directory change the sync sees. `[UNVERIFIED]` whether DirSync returns `nTSecurityDescriptor`
   changes without the object-security flag; T-1019 must settle it. If it does not, the column is
   labelled with the full-sync age.

**Enhancement E-S1 (v1).** The report tells the truth where ME reads a flag AD ignores, and says
"Not confirmed" instead of a quiet false. Proof: AC-S04, AC-S05.

## 5. User reports over new attributes (batch 6)

All use `inventory.users` extended by the sync-set list in §10 (D11). Every new column is
registered, typed and non-secret (D8); no binary is stored or returned. The 2a probable-service-
account rules do not apply (these are not expiry reports).

### 5.1 USR-07 Sign-in and access settings

| ME names (presets) | Definition | Default columns |
| --- | --- | --- |
| Dial-in Allow Access | `msNPAllowDialin` is TRUE | Name, Logon name, Domain, OU path, Dial-in access, Status |
| Dial-in Deny Access | `msNPAllowDialin` is FALSE. **Absent** is a third state, "Controlled by network policy (NPS)", and is **not** listed as Deny; the header reads "n users controlled by NPS not listed · Show" ([attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msnpallowdialin)). ME's treatment of absent is `[UNVERIFIED]` | same |
| Smart Card Enabled Users | `userAccountControl` flag `SMARTCARD_REQUIRED` (0x40000). The column says "Smart card required": the flag means required, not "has a certificate" `[UNVERIFIED]` that ME means the same by "enabled with smart card login permissions" | Name, Logon name, Domain, OU path, Smart card required, Password state, Status |
| Logon Hour Based Report | Users with a `logonHours` restriction; parameters: mode (permitted or restricted), days, start and end hour, **time zone** (default the viewer's). `logonHours` is 21 bytes, one bit per hour from Sunday 00:00 **UTC**; absent means unrestricted ([attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-logonhours)). The chosen zone is converted before comparing and shown on the report | Name, Logon name, Domain, OU path, Permitted hours (summary, with zone), Status. Default preset (no parameters): users with any restriction |

### 5.2 USR-08 Profile settings

| ME names (presets) | Definition | Columns |
| --- | --- | --- |
| Photo Based Reports (presets: with photo, without photo) | `thumbnailPhoto` or `jpegPhoto` present. **Presence only**: the bytes are neither stored nor returned. ME's page also names `thumbnailLogo` and `photo` `[ME-HELP]`; they are not synced here | Name, Logon name, Domain, OU path, Has photo, Status |
| Users With Logon Script · Users Without Logon Script | `scriptPath` has a value / has none. The header states "Scripts assigned through Group Policy are not visible here" (consult) | Name, Logon name, Domain, OU path, Logon script (the value, a path relative to NETLOGON), Status |

### 5.3 USR-09 Skype for Business / Lync

ME names: Skype for Business/Lync Enabled Users · Skype for Business/Lync Disabled Users.
Definition: `msRTCSIP-UserEnabled` TRUE / FALSE. The attribute exists only where the schema was
extended: for a domain without it the report does not run for that domain and says "Schema
extension not present" in the header, and never returns an empty list that looks like "nobody".

### 5.4 Scope note

Dial-in, smart card and logon hours are access-control-relevant, so the build ticket carries
`security-sensitive` and the rows obey the 2a trimming rules unchanged.

### 5.5 USR-11 Attribute completeness

| ME names (presets) | Definition |
| --- | --- |
| Users With Empty Attributes | Users with no value in the chosen column(s); "any" or "all" of several |
| Users With Duplicate Attributes | Users sharing a value in the chosen column within the runner's scope |

The attribute is **chosen from a closed list of registered columns** (picker; the admin never types
an attribute name or a filter). First list: e-mail, employee ID, department, title, company,
telephone, mobile, description, display name, manager (empty only). Default on open: Empty →
e-mail; Duplicate → e-mail. **Parity gap, stated:** ME also takes custom attributes
`[ME-HELP]`; custom attributes arrive with the builder (2c, ADM-097). Duplicates are computed **over
the runner's scope only** and the header says so, so a twin outside the scope is neither shown nor
disclosed (consistent with post-trim counts, reports-2a §8.1). Columns: Name, Logon name, Domain, OU
path, the chosen attribute's value, Duplicate count (duplicate preset), Status.

## 6. Groups, managers and computers (batch 7 and 9)

### 6.1 USR-12 Managers

| ME names (presets) | Definition | Parameters |
| --- | --- | --- |
| All Managers | Users with at least one direct report, derived from other users' `manager` link (`directReports` is a back-link, not delivered by sync) | none; columns: Name, Logon name, Domain, OU path, Direct reports (n), Status |
| Manager Based Users | Users whose `manager` is one of the chosen managers (direct reports) `[ME-HELP]` | **Requires one or more managers** (picker, like GRP-02). Without one the report shows "Pick a manager", an instruction not an error |

Depends on the `manager` attribute (T-1041, also "Users Without Managers" in 2a). Indirect reports
are not in this slice (manager chains may cycle; a later enhancement).

### 6.2 USR-13 Users in more than one group

ME name: Users in More than One Group (ME's user page; ME's group page does not list it
`[ME-HELP]`). Default: users with two or more **explicit** group memberships, the primary group
excluded, because the primary group (Domain Users in a default domain) is a membership everyone
has and would list every user. Switches: "Count the primary group" and "Count nested groups"
(effective, via the DM-17 closure, cycle-safe as reports-2a §6.6). Columns: Name, Logon name,
Domain, OU path, Groups (n), Member of (list, the first 5 with "+n"), Status. ME's count rule is
`[UNVERIFIED]` and goes to the ADMP check.

### 6.3 GRP-06 Users only in Domain Users

ME name: Users Only Members of Domain Users Group (ME's heading: "Users only Member of 'Domain
Users Group'" `[ME-HELP]`). Definition: the user's primary group is the domain's Domain Users
(RID 513) and the user is a member of no other group. A user whose primary group is something
else is not in this report unless explicitly added to Domain Users (consult). It is the Domain
Users subset of GRP-04 (reports-2a §6.6) and uses the same edge data (DM-17) so that the primary
group counts and a group with more than 1,500 members contributes every edge. A separate
definition keeps GRP-04's locked version unchanged. Columns: Name, Logon name, Domain, OU path,
Primary group, Created, Last logon (replicated), Status. The header lists the domains covered.

### 6.4 CMP-04 Computers with duplicate attributes

ME name: Computers with Duplicate Attributes ("computers sharing duplicate values for a chosen
attribute" `[ME-HELP]`). Over `inventory.computers`; choice is a closed list: DNS host name,
service principal name (each value; a duplicate SPN is a Kerberos fault, the most useful case),
operating system is **not** offered (duplicates are meaningless). Same scope-only duplicate rule as
§5.5. Default: DNS host name. Columns: Name, DNS name, Domain, OU path, the chosen value, Duplicate
count, Status, Created.

### 6.5 CMP-05 Managed and Unmanaged Computers (gated on T-1014)

ME names: Managed Computers · Unmanaged Computers. ME's page: computers that have / have no "an
assigned manager" `[ME-HELP]`, i.e. `managedBy` set / not set (the same meaning as ME's Managed
Groups, which 2a ships as GRP-01). Columns: Name, DNS name, Domain, OU path, Managed by, Status,
Created. Needs `managedBy` on `inventory.computers` (D2 does not carry it; D11). **Gate:** this
report is built only after T-1014 puts the definition in the research. If T-1014 leaves it
`[UNVERIFIED]`, this row is out and the name counts drop by 2.

## 7. ADM-092: policy, printers, replication (batches 8 and 10)

New library category **Domain and DCs**.

### 7.1 SYS-01 Account policies (batch 8)

| ID | Report | ME names (presets) | Dataset | Default columns |
| --- | --- | --- | --- | --- |
| SYS-01 | Account policies | Password Policy · Account Lockout Policy | `inventory.policies` (D12, built on the D4 inputs of reports-2a) | One row per policy: the domain's policy and each fine-grained policy (PSO), with Precedence, Applies to (direct targets, with count) and, per preset, the password columns (minimum length, history, maximum age, minimum age, complexity, reversible encryption) or the lockout columns (threshold, duration, observation window) |

Rules:
1. The domain values are the attributes on the domain head (`minPwdLength`, `pwdHistoryLength`,
   `maxPwdAge`, `minPwdAge`, `pwdProperties`, `lockoutThreshold`, `lockoutDuration`,
   `lockoutObservationWindow`), because the attribute is the effective truth; the Default Domain
   Policy GPO normally agrees ([policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy)).
   `pwdProperties` bits shown: complexity (0x1) and reversible encryption (0x10). Age and duration
   use the reports-2a §6.4 codec: 0 or minimum signed 64-bit is shown as "Never" / "Until an
   administrator unlocks".
2. PSOs are `msDS-PasswordSettings` objects with `msDS-PSOAppliesTo` (direct targets: users and
   global security groups; **not** the resultant set) and a precedence
   ([PSOs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies)).
   The report lists policies and their direct targets. Which policy wins for a user is resolved at
   run time by the 2a resolver and shown per user in PWD-01/USR-05 ("Policy source"); this report
   links to them and does not claim a per-user resultant.
3. **PSOs are readable by Domain Admins only by default** (consult). If the connection account
   cannot read them, the report shows the domain row and a banner "Fine-grained policies could
   not be read: <reason>", and states that users may be governed by policies not shown. It never
   shows "no fine-grained policies" for an unreadable container (same rule as "Unknown (input
   missing)", reports-2a §6.4).
4. Enhancement **E-S2 (v1)**: both presets in one view with the PSOs and what they apply to, and
   each PSO value shown with its difference from the domain value ("stricter" / "weaker"). ME's
   page lists the two policies per domain `[ME-HELP]`; whether it shows PSOs is `[UNVERIFIED]`.
5. Policy read time is the freshness (`as_of` = the policy sync read).

### 7.2 SYS-02 Published printers (batch 10)

| ID | Report | ME names | Dataset | Default columns |
| --- | --- | --- | --- | --- |
| SYS-02 | Published printers | Printer Reports | `inventory.printers` (D13) | Printer name, Print server, Share / UNC path, Location, Driver, Colour, Duplex, Domain, OU path of the server, Created, Observed at |

ME's page: "the list of Printers for the selected domain(s)" `[ME-HELP]`; its data source and columns
are `[UNVERIFIED]` (not on its Computer page either). Ours reads `printQueue` objects, which are
children of the host server's computer object
([printQueue](https://learn.microsoft.com/en-us/windows/win32/adschema/c-printqueue)). **Published
is not installed:** only shared printers whose owner published them appear, and the directory
removes entries whose server is unreachable `[UNVERIFIED]` interval. The report is named
"Published printers", the header says so and shows the as-of date. Scope: by the server's ancestry.
Attributes: `printerName`, `serverName`, `uNCName`, `printShareName`, `location`, `description`,
`driverName`, `printColor`, `printDuplexSupported`.

### 7.3 SYS-03 DC replication status (batch 10, `security-sensitive`)

| ID | Report | ME names | Dataset | Default columns |
| --- | --- | --- | --- | --- |
| SYS-03 | DC replication status | DC Replication Status | per-DC read, **not stored** (D14) | Domain controller, Domain, Partition, Partner (source DC), Last attempt, Last success, Consecutive failures, Last error (text), Status, Lingering-object risk, Read at |

ME's report "fetches the replication status of the selected domain controller(s)" with filters
"AD Replication Status" and "Destination DC Status" and an error-detail link `[ME-HELP]`. Ours:

1. **Read per DC, inbound view.** Each DC reports only its own inbound neighbours, so the run reads
   every DC in scope. Attributes: the replication-neighbour constructed attributes
   (`msDS-ReplAllInboundNeighbors`, `msDS-ReplPendingOps`, `msDS-ReplConnectionFailures`,
   `msDS-ReplLinkFailures`), with `repsFrom` on the partition head as the lowest-privilege
   fallback. Their location (RootDSE or partition head) and the right needed ("Monitor Active
   Directory Replication", the DRS `GetReplInfo` right) are `[UNVERIFIED]` and `[LAB: Windows]`.
   Samba is expected to return partial data `[UNVERIFIED]`: a value the DC does not return is
   "Not reported", never "healthy".
2. **Coverage as in reports-2a §6.5**: "Read from 5 of 6 DCs", the unreachable DC and its error
   named, a row for every DC that did not answer. Never "no problems" with partial coverage.
3. **Status** is derived, not stored: Healthy (last success within the threshold and zero
   failures), Warning, Failing (failures > 0 or last success older than the threshold), Not
   reported. The thresholds are tenant-editable with defaults a `[PROPOSED]` 1 hour warning and 24
   hours failing, for `ad-expert` and `reporting-engineer` to confirm.
4. **Lingering-object risk (an indicator, not detection).** "At risk" when a partner's last
   success is older than the forest's tombstone lifetime. The column heading and the AC forbid the
   word "detected". Proving a lingering object needs `DsReplicaVerifyObjects` and is out (§8).
5. **Last error text** is shown and escaped like any attacker-controlled string (DC messages are
   not attacker-controlled, but the same encoder applies, FF-SP4).
6. **Cap and cadence.** Reads are per DC and per partition (a handful per DC), not per object, so
   the object-level read cap of §6.5 does not apply. This report has its own bound: one concurrent
   read per DC and a hard limit of 100 DCs per run (`[PROPOSED]`, calibrated in B13). **Amendment
   to FR-28 (§9):** the daily floor of the per-object per-DC reports (USR-04, PWD-03) does not
   apply here; this report follows the 1-hour floor of §8.4.
7. **Enhancement E-S3 (v1):** a failing row says in the row what the error means and what to do,
   using Microsoft's documented error meanings. Wording is `ad-expert`'s; no remedy text ships
   without a source.
8. **No "Trigger replication" button.** ME has one `[ME-HELP]`; that is a write, a 2b Action.

## 8. Kept out of this slice

| Item | Reason | Unblocker |
| --- | --- | --- |
| BitLocker Recovery Keys, Enabled, Disabled Computers | See §2: secrets, and escrow is not enablement | 2b decision on `ReadSecret` and an escrow-only sync |
| Terminal Services (Users' Terminal Services Properties, Users with Terminal Server Access) | See §2 | F3 |
| GPO Linked OUs, GPO Inheritance Blocked OU | See §2 | E-008 spec |
| Lingering Objects | See §2 and §7.3 | F2 |
| Exchange, GPO, NTFS, M365, Google families | Matrix priority | their milestones |
| Act on rows (restore, delete, trigger replication) | Reports-2a FR-13 | ADM-098, 2b |

## 9. Parity differences chosen on purpose, and amendments to reports-2a

| # | Difference | Why |
| --- | --- | --- |
| P1 | Cannot Change Password reads the access-control entries, not ME's flag | AD ignores the flag |
| P2 | "Modified" ignores automatic updates by default | `whenChanged` moves on every logon-time update; the noise set is shown and switchable |
| P3 | Dial-in Deny does not list users controlled by NPS | Absent is not Deny |
| P4 | Users in More than One Group excludes the primary group by default | Otherwise it lists everyone |
| P5 | Empty/Duplicate Attributes: registered columns only | Custom attributes arrive with the builder |
| P6 | No actor on Recently Deleted/Modified | DM-18.I3 |

Amendments to reports-2a (to be folded into it by its owner, with the version note):
- **A1 (§6.1 rule 6):** the Deleted presets of §4.1 list deleted, recycled and purged objects.
- **A2 (FR-28, §8.4):** the daily floor applies to per-object per-DC reads only; SYS-03 follows the
  1-hour floor.
- **A3 (§6.3):** the table is superseded by §2 here.

Decisions (logged here, vetoable by the CEO, none directional): the noise default (§4.1.2); the
day-one `when_changed` fallback (§4.1.5); the four-valued CCP state (§4.2); the "Published printers"
naming; the closed attribute list (§5.5); keeping Terminal Services out.

## 10. Datasets, build handoffs and follow-ups

Attributes and objects outside the reports-2a sync set (D1 to D5), so the dataset tickets can be
sized. None is a secret (D8).

| ID | Dataset / change | Needs | Ticket |
| --- | --- | --- | --- |
| D10 | `inventory.object_changes` over DM-18 and the show-deleted lifecycle: kind, object GUID, change kind, attribute names, `origin` time, observed time, state, last-known parent and ancestry, history start per connection | `isDeleted`, `lastKnownParent`, `isRecycled`, `msDS-ReplAttributeMetaData` (constructed, read for flagged objects from the same DC, not delivered by DirSync `[consult]`), `msDS-ReplValueMetaData` for groups; per-domain `msDS-deletedObjectLifetime` / `tombstoneLifetime` | T-1109 |
| D11 | `inventory.users` and `inventory.computers` extension | users: `msNPAllowDialin`, `scriptPath` (value), `msRTCSIP-UserEnabled` (tri-state with "schema absent"), `logonHours` (as 168 bits), photo presence (`thumbnailPhoto`, `jpegPhoto`: boolean only), `mail`, `employeeID`, `department`, `title`, `company`, `telephoneNumber`, `mobile`, `description`, `manager` (T-1041); SMARTCARD_REQUIRED already in D1; derived "direct report count". Computers: `dNSHostName` (present), `servicePrincipalName` values, `managedBy` (CMP-05 only). The `description`/personal attributes are erasable under X11 | T-1111 |
| D12 | `inventory.policies` | Domain head attributes in §7.1; `msDS-PasswordSettings` with `msDS-PSOAppliesTo` and precedence; "readable?" flag per connection | T-1114 and D4 of 2a |
| D13 | `inventory.printers` | `printQueue` objects and the attributes of §7.2 | new (batch 10) |
| D14 | Per-DC replication read | `ReadReplicationStatus{DC}` connector call (not `ReadPerDC`, which is per object), `RunResult` coverage as in 2a | new (batch 10) |
| D15 | Security-descriptor state on `inventory.users` | Four-valued state from the T-1019 read path, DACL only | T-1106, T-1019 |

For D15 the read asks for the DACL only (no SACL, which needs a privilege we must not request).
Under default permissions an ordinary read right on users suffices; where an organisation removed
it, rows show "Not confirmed" `[UNVERIFIED]` for hardened domains.

**Handoffs.**
- `directory-engineer` (T-1019, T-1106): replace the boolean with the four-valued state of §4.2.
- `solution-architect`: new derived fragments for the logon-hours test (`permitted_at` in a zone),
  scope-only duplicate counting, noise-filtered change aggregation, per-policy rows; confirm each is
  expressible in the closed AST (FR-05).
- `security-architect` tags: PWD-04 (T-1019/T-1106/T-1107), D10 (T-1109), D11 (T-1111), SYS-03
  (D14), USR-07 (dial-in, smart card, logon hours).
- `product-designer`: three screens that are not the 2a grid: the change-history row detail (§4.1),
  the PSO table with deltas (§7.1), the per-DC replication grid with the unreachable-DC rows (§7.3).

**Follow-ups filed (backlog):** F1 = T-1120, ADMP comparison of this slice's `[UNVERIFIED]`
meanings; F2 = T-1121, lingering-object detection spec (ad-expert, with security-architect review);
F3 = T-1122, Terminal Services `userParameters` decoder spec; F4 = T-1123, design of the three
screens above.

## 11. Experience target

Same flow as reports-2a Flow A: `/`, type the report or ME name, Enter lands on results with no
Generate step: **3 interactions / 1 typed field / 2 screens** (reports-2a §5, benchmark T20 steps
1 to 3), including for ME names in this slice. Reports that require a pick (Manager Based Users,
Logon Hour parameters, Empty/Duplicate attribute) add the picker: target **≤ 5 / 2 / 2**, set with
`product-designer` at F4 (`[PROPOSED]`). The admin never has to: write a filter or an attribute name;
know that the flag ME reads is not the one AD honours; know that "modified" is noisy; work out
whether an unknown means no.

## 12. Platform matrix

`✓` supported · `◐` partial as stated · `✗` not in this slice, with the ticket. Profiles `windows`
and `linux-oci` behave identically (ADR-0002 rule 1; reports are server-side). The Windows-profile
GA gate is as in reports-2a §10. No DC-side or Windows-native component is added: every read is
LDAP from our server, so no Windows Server version of an added component applies. Managed DCs are
Windows Server 2016 to 2025 (ADR-0002). Functional levels: `lastLogonTimestamp` and PSOs need 2003
and 2008 or later respectively (reports-2a §10); the Recycle Bin needs forest level 2008 R2 or
later ([Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)).

| Report | AD on-prem WS2016 to 2025 | Entra cloud-only | Hybrid synced objects | Samba AD (CI lab) | `windows` | `linux-oci` |
| --- | --- | --- | --- | --- | --- | --- |
| PWD-04 | ✓ | ✗ → T-1018 | ◐ AD side only | ◐ the DACL read is testable; assert on ACEs, not on the flag (lab note) | ✓ | ✓ |
| USR-06, GRP-05, CMP-03, CTC-02, OU-02 | ✓ with the Recycle Bin on; with it off, deleted rows are sparse (§4.1.7) | ✗ → T-1018 | ◐ | ◐ originating-time metadata and show-deleted behaviour `[UNVERIFIED]` | ✓ | ✓ |
| USR-07, USR-08, USR-11 | ✓ | ✗ | ◐ | ✓ attributes are plain LDAP | ✓ | ✓ |
| USR-09 | ✓ where the schema was extended; "Schema extension not present" otherwise | ✗ | ◐ | ◐ schema usually absent | ✓ | ✓ |
| USR-12, USR-13, GRP-06, CMP-04, CMP-05 | ✓ | ✗ | ◐ | ✓ | ✓ | ✓ |
| SYS-01 | ✓ domain row; PSO rows need level 2008+ and the read right | ✗ | ◐ | ◐ PSO behaviour `[UNVERIFIED]` on Samba, `[LAB: Windows]` | ✓ | ✓ |
| SYS-02 | ✓ | ✗ | ◐ | ✓ if `printQueue` objects are seeded | ✓ | ✓ |
| SYS-03 | ✓ `[LAB: Windows]` for attribute location and right | n/a (no DCs) | ◐ AD DCs only | ◐ expected partial, rows say "Not reported" | ✓ | ✓ over the same LDAP transport |

Cells that are partial are decisions: Samba results prove the plumbing and the LDAP-readable
truth; they do not prove the Windows-only behaviour listed, which waits for `[LAB: Windows]`.

## 13. Security and audit

- **Directory rights.** PWD-04 needs read of each user's DACL (default Authenticated Users read
  suffices). SYS-01 PSOs need read of the Password Settings Container (Domain Admins by default; a
  delegated read otherwise; an unreadable container is stated, never hidden). SYS-03 needs a
  replication-monitoring read `[UNVERIFIED]`: **this may contradict reports-2a §9's "no new
  directory right"**, so `security-architect` decides before D14 is built. Deleted-object reads need
  the right to see the Deleted Objects container (research notes ADMP needs manual `dsacls` grants
  for restores; reading is a different, lower right `[UNVERIFIED]`). No report writes to a directory.
- **Disclosure.** USR-06 and the other change reports disclose that an object existed and when it
  was deleted; scope trims by stored ancestry (§4.1.8). Duplicates are counted in scope only (§5.5).
  Photo and logon-script reports return presence and path text, never bytes. PWD-04 and USR-07 name
  accounts with weakened or unusual protection: they are the same Tier-0-adjacent disclosure as the
  2a reports (reports-2a §9), covered by `reports.run`.
- **Safe primitives.** Report SQL, scope and export encoders as reports-2a §9. The logon-hours,
  attribute and manager pickers send registry IDs, never text. Attribute values and error strings
  are escaped on every output (TM-X3). The `userParameters` blob is deliberately not decoded (F3).
- **Audit.** Run, export, download and schedule events as reports-2a §8.6. Nothing new is written
  to a directory, so no activeDIQ change event is added.

## 14. Functional requirements

| ID | Requirement | Parity |
| --- | --- | --- |
| FR-S01 | The library MUST add the reports of §4 to §7 (17 firm, plus CMP-05 only when T-1014 confirms) in the category and with the ME names, presets, columns and filters stated there, and each ME name MUST resolve to its report and preset (FR-02) | ADM-084…089, ADM-092 |
| FR-S02 | A change report MUST show "changed at" with its basis, hide the noise set with a count and a switch, show attribute names only, show no actor, state where history starts, and apply the day-one fallback of §4.1.5 | ADM-084, 086, 087, 089 |
| FR-S03 | Recently Deleted MUST list deleted, recycled and purged objects within scope, show State and "Restorable until" as "up to", mark non-retained fields as "Not retained by AD", and MUST NOT list an object whose ancestry is unknown | same |
| FR-S04 | PWD-04 MUST use the four-valued stored state of §4.2, MUST NOT read a descriptor at run time, MUST count "Not confirmed" in the header and MUST NOT list it as a match or as "No deny ACE" | ADM-085 |
| FR-S05 | Attribute-state reports MUST distinguish absent from false where the directory does (dial-in, Skype/Lync schema absent) and MUST NOT return an empty list for a domain they cannot evaluate | ADM-084 |
| FR-S06 | Empty/Duplicate Attributes MUST accept only registered columns and count duplicates within the runner's scope | ADM-084, ADM-087 |
| FR-S07 | Group-derived reports (USR-13, GRP-06) MUST count the primary group as stated in §6.2 and §6.3 and MUST include every edge of a group with more than 1,500 members | ADM-084, ADM-086 |
| FR-S08 | SYS-01 MUST list the domain policy and every readable PSO with direct targets and MUST state when PSOs were unreadable | ADM-092 |
| FR-S09 | SYS-03 MUST read each in-scope DC separately, show coverage, show "Not reported" for any unanswered value, and MUST NOT use the word "detected" for the lingering-object indicator | ADM-092 |
| FR-S10 | No kept-out item of §8 MAY appear as a dead control, a search hit or a preset | house rule 6 |

## 15. Acceptance criteria

Ground truth is an LDAP query or read on the Samba lab unless stated (AC-23 pattern); a check that
only a real ADManager Plus install can settle is marked **[ADMP]** and lives in F1 (T-1116/T-1117
pattern): **no AC here claims a match with ManageEngine.** Evidence names the artefact
`qa-verifier` produces. `[LAB: Windows]` criteria are reported separately until run.

```
AC-S01 (FR-S01, ticket acceptance 1)
Given the shipped library after batches 4 to 10
When the definitions are compared to §4 to §7
Then every report equals its row in ID, category, dataset, default columns, default filters and
  ME names, every ME name resolves (FR-02), and no §8 item is searchable
Evidence: reports_library_matches_spec test; crosswalk.tsv diff

AC-S02 (FR-S02)
Given a lab with a user edited 2 days ago, a user deleted 3 days ago, one edited 40 days ago, and
  logon-time updates on 50 other users
When Recently Modified Users runs with the default 7-day period
Then only the user edited 2 days ago is listed, with the changed attribute names and Basis, the
  header reads "50 automatic updates hidden", and the switch lists them
Evidence: lab test versus the seeded list

AC-S03 (FR-S02)
Given a connection first synced 3 days ago and an object whose when_changed is 10 days ago
When Recently Modified runs for 30 days
Then the header says "Change history starts <date>", and the object is listed with Basis
  "whenChanged read from <DC>"
Evidence: test with seeded history start

AC-S04 (FR-S04, E-S1)
Given a user with both deny ACEs, one with one deny ACE, one with neither, one with the
  userAccountControl "Password Cannot Change" bit set and no ACEs, and one whose descriptor is unreadable
When Users with Cannot Change Password runs
Then the first two are listed as Blocked and Blocked (one deny ACE only); the bit-only user is
  not listed; the unreadable user is not listed and the header counts "1 not confirmed"
Evidence: lab test asserting on the DACL, not on the bit

AC-S05 (FR-S04)
Given the report definition
When it runs
Then the run record shows no directory read of any descriptor, and the column is the stored state
Evidence: definition test; connector call log empty

AC-S06 (FR-S03)
Given one object deleted with the Recycle Bin on (restorable), one recycled, one purged from the
  directory, and one with unknown ancestry
When Recently Deleted Users runs for 365 days
Then the first three are listed with State and "Restorable until" shown as "up to", the purged one
  from history, and the fourth is neither listed nor counted
Evidence: lab test `[LAB: Windows]` for recycled; table test elsewhere

AC-S07 (FR-S03)
Given a forest with the Recycle Bin off and a tombstone with no retained name
When Recently Deleted Computers runs
Then the row shows "Not retained by AD" in the name fields and the GUID, never a blank
Evidence: test

AC-S08 (FR-S05)
Given users with msNPAllowDialin TRUE, FALSE and absent
When Dial-in Allow Access and Dial-in Deny Access run
Then Allow lists TRUE only, Deny lists FALSE only, and the header counts the absent as controlled by NPS
Evidence: lab test versus (msNPAllowDialin=TRUE) and (msNPAllowDialin=FALSE). [ADMP] for ME's treatment of absent

AC-S09 (FR-S05)
Given a domain whose schema has no msRTCSIP-UserEnabled
When Skype/Lync Enabled Users runs
Then the report does not run for that domain and says "Schema extension not present", and it does not return zero rows
Evidence: Samba lab test (schema absent)

AC-S10 (FR-S01)
Given users with and without thumbnailPhoto or jpegPhoto, a scriptPath, a SMARTCARD_REQUIRED flag
When the photo, logon script and smart card presets run
Then rows equal (|(thumbnailPhoto=*)(jpegPhoto=*)), (scriptPath=*), (userAccountControl:1.2.840.113556.1.4.803:=262144), and no photo bytes appear in the API, the grid or an export
Evidence: lab comparison; response and file inspection

AC-S11 (FR-S01)
Given users with logonHours allowing 08:00 to 18:00 UTC Monday to Friday, one unrestricted, one fully blocked
When Logon Hour Based runs for "permitted Tuesday 09:00" in UTC and again in a zone at +05:30
Then the permitted set is correct in both zones, the zone is shown, and the unrestricted user is permitted in both
Evidence: table-driven test plus lab

AC-S12 (FR-S06)
Given a lab with two users sharing an e-mail value, one of whose twins is outside the runner's scope
When a runner scoped to one twin runs Users With Duplicate Attributes on e-mail
Then neither is reported as a duplicate, the header says "duplicates within your scope", and no count reveals the twin
Evidence: scoped integration test

AC-S13 (FR-S06)
Given a request naming an attribute that is not a registered column, or a secret attribute
When Users With Empty Attributes is submitted
Then it is refused as an unregistered column and no query runs
Evidence: API negative test (FR-05, AC-29 pattern)

AC-S14 (FR-S07)
Given a user whose primary group is not Domain Users, a user in two explicit groups, a user only
  in Domain Users, and a group with 1,600 members
When Users in More than One Group and Users Only Members of Domain Users Group run
Then each lands in the right report, the primary-group switches change counts as stated, and the 1,600 members are all counted
Evidence: lab test versus (&(primaryGroupID=513)(!(memberOf=*))) and a scripted count of memberOf; [ADMP] for ME's counting rule

AC-S15 (FR-S01)
Given managers with direct reports
When All Managers and Manager Based Users run
Then All Managers lists users with at least one direct report; Manager Based Users with no manager chosen shows "Pick a manager" and with one chosen lists that manager's direct reports
Evidence: lab test versus (directReports=*) and (manager=<dn>)

AC-S16 (FR-S06)
Given computers sharing a DNS host name and a duplicated SPN
When Computers with Duplicate Attributes runs on each
Then both groups are listed with Duplicate count, within the runner's scope
Evidence: lab test

AC-S17 (FR-S01, gate)
Given T-1014 has not confirmed ME's meaning of Managed Computers
When the library is listed
Then CMP-05 is absent. Given it has confirmed, Then CMP-05 lists computers with managedBy set or not set
Evidence: library test; lab test versus (&(objectClass=computer)(managedBy=*))

AC-S18 (FR-S08)
Given a domain policy and two PSOs of different precedence applied to a group and a user
When Password Policy and Account Lockout Policy run
Then the domain row and both PSO rows show their values, direct targets and precedence, with the 0 and minimum-int64 codec applied
Evidence: lab test versus reads of the domain head and the Password Settings Container; `[LAB: Windows]` for resultant behaviour

AC-S19 (FR-S08)
Given a connection account that cannot read the Password Settings Container
When SYS-01 runs
Then the domain row is shown with the banner "Fine-grained policies could not be read" and no row or text says there are no PSOs
Evidence: test with a restricted account

AC-S20 (FR-S01)
Given printQueue objects published on two servers, one server unreachable and pruned
When Printer Reports runs
Then it lists the printers present, named "Published printers", with as-of date
Evidence: lab versus (objectClass=printQueue). [ADMP] for ME's source and columns

AC-S21 (FR-S09)
Given 6 DCs of which one is unreachable and one fails inbound replication from a partner
When DC Replication Status runs
Then 5 of 6 are read and the sixth has its own row with the error, the failing partner shows Failing with its consecutive failures and last error, and nothing says "no problems"
Evidence: `[LAB: Windows]` test versus repadmin /showrepl; Samba shows "Not reported" for unreturned values

AC-S22 (FR-S09)
Given a partner whose last success is older than the tombstone lifetime
When DC Replication Status runs
Then the indicator reads "At risk" and no label or text on the report uses "detected" for lingering objects
Evidence: UI text test; seeded values

AC-S23 (FR-S01)
Given the largest lab (100,000 users, a group of 6,000 members)
When each batch-7 and batch-6 report runs with defaults
Then the first 50 rows and the count return within the reports-2a §5 budget
Evidence: scale tier benchmark (B13)

AC-S24 (FR-S01, reports-2a AC-06)
Given a runner scoped to one OU
When every report of this slice runs
Then rows, totals, header counts ("n hidden", "n not confirmed") and "checked n objects" exclude everything outside the OU
Evidence: integration test versus a direct LDAP read of that OU

AC-S25 (empty states)
Given a lab with none of the matching objects
When each report runs
Then it shows "No <objects> match. n objects were checked in m domains as of <time>" and the filters offered for removal, never a blank grid
Evidence: UI recording

AC-S26 (FR-S10)
Given the library UI and API
When searched for BitLocker, Terminal Services, Lingering Objects, GPO Linked OUs
Then none opens a report, a preset or a disabled control
Evidence: search test; UI recording

AC-S27 (partial failure)
Given a run over two domains where one has not synced and one is stale
When any report of this slice runs
Then the other domain runs, the first is listed as skipped, the second carries the Stale banner, and exports and schedules carry both labels (reports-2a AC-10/AC-11)
Evidence: test
```

## 16. Open questions

| # | Question | Owner | Blocks |
| --- | --- | --- | --- |
| S1 | Does DirSync return `nTSecurityDescriptor` changes without the object-security flag? | directory-engineer in T-1019 | Freshness label of PWD-04 only |
| S2 | Location and right for the replication-neighbour attributes; Samba coverage | ad-expert, `[LAB: Windows]` | D14 build; SYS-03 right (security-architect) |
| S3 | ME's meanings marked `[UNVERIFIED]` here (Dial-in absent, Smart Card, multi-group count, Domain-Users-only, printers, modified) | test-engineer, F1 | Nothing; no match claimed |
| S4 | Replication status thresholds (1 h, 24 h) | ad-expert, reporting-engineer | Defaults apply |
| S5 | T-1014 confirmation of Managed/Unmanaged | market-analyst | CMP-05 only |

No question is directional: nothing needs the CEO. The only commercial-looking item, how many
reports count towards the PRD's "60+", is a reading of an existing claim by the `project-manager`.
