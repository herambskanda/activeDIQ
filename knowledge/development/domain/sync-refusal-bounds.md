---
title: "Sync mapper refusal bounds vs AD schema rangeUpper"
date: 2026-11-07
updated: 2026-11-13
status: draft
owner: directory-engineer
author: directory-engineer
ticket: T-1250
---

# Sync mapper refusal bounds vs AD schema rangeUpper

An entry the mapper refuses (`internal/directory/sync`) never reaches `directory_objects`. A bound that a
non-admin principal can exceed is therefore a way to hide an object from inventory reports. Bounds are
**characters** (what rangeUpper counts), not bytes (T-1250 changed the check from `len` to rune count; the
store's own check in `inventory.validateObservation` and the `length()` CHECKs are characters too).

rangeUpper values below were **read from the schema NC of the Windows Server 2025 lab DC dc1 on 2026-11-13
(T-1880)**: all seven attributes that carry one match; `operatingSystem` / `operatingSystemVersion` carry **no**
rangeUpper on Windows either (the 128 / 24 first written here were wrong; the mapper's 1024 stands).
Writers: "creator" is the principal that created a computer under MachineAccountQuota.

| Attribute | Mapper bound (chars) | AD rangeUpper | Default non-admin writers | Verdict |
| --- | --- | --- | --- | --- |
| sAMAccountName | 256 | 256 | computer creator (validated: `<=20`/ends `$`) | equal; was 256 **bytes**, fixed |
| userPrincipalName | 1024 | 1024 | none by default (self: no) | equal; was bytes, fixed |
| displayName | 1024 | 256 | self (Personal-Information set, where delegated), computer creator | wider than AD |
| mail | 1024 | 256 | self (delegated) | wider than AD |
| company | 1024 | 64 | self (delegated) | wider than AD |
| description | 4096 (first value) | 1024, multi-valued | computer creator | wider than AD |
| dNSHostName | 2048 (was 1024) | 2048 | computer creator (validated write) | equal; was too small, fixed |
| operatingSystem / Version | 1024 | none in the schema (T-1880) | computer itself | no schema bound |
| managedBy (DN text) | 4096 | DN syntax | computer creator | DN limits tighter in AD [UNVERIFIED] |
| msDS-AllowedToDelegateTo | 1024 each, 10000 values | 1024 each | SeEnableDelegationPrivilege (admin) | admin only |
| RDN / DN | 1024 chars / 4096 bytes | RDN 64 / DN 255 practical | creator | wider than AD |
| objectClass | 100 | n/a (schema names) | none | n/a |
| member | 100000 values | unlimited (ranged) | group owners | admin-scale; see below |
| attribute bag | 60 KiB JSON | n/a | derived | worst case below |

## What can still refuse a non-admin-controlled object

* `CodeBadText`: NUL or invalid UTF-8. **Unpaired-surrogate hiding is not reachable over LDAP on Windows
  Server 2025 (T-1880, below):** AD stores the surrogate but every LDAP read returns valid UTF-8 (U+FFFD), so
  the mapper never sees bad text from it. Residual: a read path that returns raw UTF-16 (DirSync / replication
  read) was not tested here.
* `CodeAttributesSize`: a bag over 60 KiB. With AD's rangeUpper values the non-admin attributes sum to under
  ~6 KiB of text (≤ 6 bytes per char as JSON `\u00XX`, ≈ 36 KiB worst case), below the bound.
* `member` over 100000 values: group owners/managers with write-member; ranged reads make larger groups a
  partial set, not a refusal, until 100000.

## Surfacing (AC2)

`DomainReport.RefusedEntries` lists up to `MaxRefusedEntries` (1000) refused entries as objectGUID plus
(attribute, code), with `RefusedOmitted` for the rest. The per-domain log line carries the first 20 as
`refused_object.N`. No value is carried. A GUID-only placeholder row was not added: the ingester upserts
whole observations, so a placeholder would blank an already-stored object's state, and a report-visible
"unreadable" state needs a store column and report semantics (follow-up ticket).

## Lab evidence and accepted residuals (T-1250)

* **Samba lab test**: `Test_lab_mapper_bounds_cover_the_schema_range_upper` (`make lab-test-sync`, tag `lab`,
  `internal/directory/sync/schema_bounds_lab_test.go`) reads `rangeUpper` from the schema NC of the running
  lab and asserts a value of exactly that many multi-byte characters maps for each attribute above. Run
  2026-11-07 on Samba: pass (sAMAccountName 256, UPN 1024, displayName 256, mail 256, company 64,
  description 1024, dNSHostName 2048; operatingSystem/Version carry no rangeUpper in Samba's schema).
  This proves Samba's schema only; the Windows twin is below. T-1880 also made it build its ldbsearch filter with
  `ldapfilter.Eq`/`Render` and fail when fewer than 7 attributes return a rangeUpper (it used to skip silently).
* **Accepted residual, tracked**: `CodeBadText` from invalid UTF-8 is not closable by widening; the
  surrogate route to it is disproved over LDAP (T-1880). The object is identified by GUID in the cycle report
  and log only; nothing outside `internal/directory/sync` consumes `DomainReport` yet.
  Tracked in T-1713 (GUID-only placeholder / U+FFFD option), T-1714 (health finding).

## Windows lab evidence (T-1880, dc1, 2026-11-13)

`lab/windows/bin/with-dc1-lock -- make lab-test-sync-windows` (tags `lab windowslab`,
`schema_bounds_windows_lab_test.go`, writer `lab/windows/bin/t1880-surrogate-write`). Log:
`runbooks/windows-lab-runs/T-1880-schema-bounds-surrogate-20261113.log.txt`.

**AC1, rangeUpper on Windows (WS2025 schema NC):** sAMAccountName 256, userPrincipalName 1024, displayName 256,
mail 256, company 64, description 1024 (multi-valued), dNSHostName 2048: each equals the table; a value of exactly
that many 2-byte characters maps. operatingSystem, operatingSystemVersion: no rangeUpper. The test pins these
and fails if the schema ever differs.

**AC2, unpaired surrogate by a MachineAccountQuota creator.** `ms-DS-MachineAccountQuota` = 10; a plain domain
user (no group memberships) created `CN=T1880PC` in `CN=Computers`. (An LDAP add by a non-admin is refused with
unwillingToPerform unless it carries `unicodePwd`, matching `dNSHostName` and `servicePrincipalName`; it also
cannot set `msDS-SupportedEncryptionTypes`.) As that creator, U+D800 alone and U+DC00 alone, and the valid pair
U+D83D U+DE00 as a control, were written to `description` and `displayName` (SAMR full name) over:

| Write path | Write accepted? | LDAP read-back | Mapper |
| --- | --- | --- | --- |
| SAMR (WinNT provider: Description / FullName) | yes | `EF BF BD` (U+FFFD) | maps, no refusal |
| ADSI LDAP provider SetInfo | yes | `EF BF BD` | maps, no refusal |
| raw LDAP, CESU-8 bytes `ED A0 80` / `ED B0 80` | yes | `EF BF BD EF BF BD` | maps, no refusal |
| valid pair (control), all three paths | yes | `F0 9F 98 80` | maps |

**Verdict for T-1713:** the hiding path is **reachable to write by a non-admin but not live**: the DC accepts the
surrogate yet returns valid UTF-8 on every LDAP read, so the mapper cannot refuse the entry with `CodeBadText`
and the object is not hidden. T-1713 should not build a fix for this route; the observable effect is silent
substitution of U+FFFD (data fidelity). Not covered: raw-UTF-16 read paths (DirSync, DRS replication) and NUL.

