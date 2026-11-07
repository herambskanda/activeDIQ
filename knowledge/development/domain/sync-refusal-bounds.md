---
title: "Sync mapper refusal bounds vs AD schema rangeUpper"
date: 2026-11-07
updated: 2026-11-07
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

rangeUpper values are from the AD schema as documented in MS-ADSC; **[UNVERIFIED] on a live schema** until
the Windows-lab ticket T-1243 reads `rangeUpper` from the schema NC (Samba's schema differs for some).
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
| operatingSystem / Version | 1024 | 128 / 24 | computer itself | wider than AD |
| managedBy (DN text) | 4096 | DN syntax | computer creator | DN limits tighter in AD [UNVERIFIED] |
| msDS-AllowedToDelegateTo | 1024 each, 10000 values | 1024 each | SeEnableDelegationPrivilege (admin) | admin only |
| RDN / DN | 1024 chars / 4096 bytes | RDN 64 / DN 255 practical | creator | wider than AD |
| objectClass | 100 | n/a (schema names) | none | n/a |
| member | 100000 values | unlimited (ranged) | group owners | admin-scale; see below |
| attribute bag | 60 KiB JSON | n/a | derived | worst case below |

## What can still refuse a non-admin-controlled object

* `CodeBadText`: NUL or invalid UTF-8. AD stores UTF-16; an unpaired surrogate written over LDAP may come
  back as invalid UTF-8 [UNVERIFIED on Windows; Samba rejects invalid UTF-8 on write]. Not closable by
  widening. It is now **identified**, see below.
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
