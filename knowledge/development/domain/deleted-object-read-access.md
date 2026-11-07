---
title: "Reading a deleted object: what the classification identity needs (restore step 7)"
date: 2026-11-07
updated: 2026-11-07
status: draft
owner: heramb
author: ad-expert
ticket: T-1633
---

# Reading a deleted object by GUID: the minimal grant (T-1633)

**Question (connector-contract §8.10.9 R2).** Kind 6 `OBJECT_RESTORE` step 7 must read a fixed attribute set of the
*deleted* target before it restores it. T-0076 showed a Reanimate-only principal gets `noSuchObject` when it reads
the target, and threat-model §6.3 R15 forbids requesting List/Read on `CN=Deleted Objects`. Can the connector's
separate classification identity read the object with a per-object grant instead?

## Answer (conclusion first)

**No. There is no per-object grant.** On Windows Server 2025 (Recycle Bin on), a non-administrator reads a deleted
user by `<GUID=…>` with the show-deleted control **only if it holds *List Contents* (`ADS_RIGHT_ACTRL_DS_LIST`,
0x4, dsacls `LC`) on `CN=Deleted Objects,<domain NC>`**. Nothing on the object, the OU or the NC root substitutes.
Without that one right the DC answers `32 noSuchObject` ("missing or not permitted"), indistinguishable from
"never existed". With it, the full R2 set is readable.

- **Minimal grant:** `LC` on the container, to the classification identity only. `Read Property` on the container is
  neither needed nor sufficient. The KB 892806 recipe (`LCRP`) grants more than the read needs.
- **That is exactly the container grant R15 forbids.** Kind 6 as written in §8.10.9 R2 (a classified, fail-closed
  step 7) **cannot ship without the grant**, and R2 told the build ticket not to work around it. This is a
  security-architect decision, not an AD-expert one (ticket T-1730). Options are at the end.
- **Samba does not tell you this.** No test of step 7 on Samba proves the Windows behaviour (§Lab reality).

## Why (the mechanism, documented)

Visibility in AD is decided by the *parent*: an object is hidden from a caller unless the caller has List Contents on
the parent, or List Object on the object when `dSHeuristics` list-object mode is on
([ADS_RIGHTS_ENUM](https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum),
[Controlling Object Visibility](https://learn.microsoft.com/en-us/windows/win32/ad/controlling-object-visibility)
`[page linked from the enum doc, not fetched]`). A deleted object's parent is `CN=Deleted Objects`, whose default
descriptor gives access only to SYSTEM and Administrators: `O:SYG:SYD:PAI(A;;KA;;;SY)(A;;LCRP;;;BA)` (**measured on
dc1**, matches the KB 892806 dsacls output and a Microsoft engineer's statement on the Samba protocol list,
[secondary](https://lists.samba.org/archive/cifs-protocol/2014-October/002552.html)). So the default read of a
deleted object by an ordinary identity is a visibility failure, not an attribute-ACL failure. The object's own
descriptor is retained and still decides *which attributes* come back once it is visible (below).

## What was measured (dc1, Windows Server 2025, level 2025, Recycle Bin on; raw: [log](../runbooks/windows-lab-runs/T-1633-deleted-object-read-20261107.log.txt))

Identities: `cls` (plain user), `cls2` (plain user + inheritable `GR` on the OU, set before the delete), `cls3`
(`cls2` + Reanimate-Tombstones on the NC root). Victims: v1 default; v3 explicit Generic-All ACE for `cls`/`cls2` on
the object before the delete; v4 explicit Deny `RP`+`RC` for `cls2` before the delete. Read = base search
`<GUID=…>`, show-deleted control (critical), SD_FLAGS 7 for `nTSecurityDescriptor`.

| Grant held by the classifier | Result reading the deleted user |
| --- | --- |
| Default rights (Authenticated Users) | `noSuchObject`. The same user reads the live object fine (all attributes) |
| Inheritable Generic Read on the OU, set before delete | `noSuchObject` |
| Explicit Generic-All ACE on the object itself, set before delete (v3) | `noSuchObject` |
| Reanimate-Tombstones on the NC root | `noSuchObject` (T-0076 said the same for a restorer) |
| `dSHeuristics` list-object mode on (3rd char `1`), with Generic Read (includes List Object) on the object | `noSuchObject`. **Inconclusive:** waited 3 s, no positive control that the mode had taken effect; it is a forest-wide hardening switch we would not ask a customer to flip anyway |
| `Read Property` on `CN=Deleted Objects` only | `noSuchObject` |
| **`List Contents` on `CN=Deleted Objects` only** | **success**, R2 set returned (v1, v3) |
| `List Contents` + `Read Property` | success, same as `LC` alone |
| `LC`, but the show-deleted control left off | `noSuchObject` |

**After `LC`, the object's retained descriptor governs attributes.** v4 (explicit Deny RP/RC for `cls2`): the entry is
returned, **zero attributes**. So an unreadable value comes back as *absent*, not as an error: the connector must treat
an absent R2 attribute on a deleted object as "unreadable" (`tier0`, fail closed), never as "not set". An `adminCount`
of 1, a delegation target and `userAccountControl` were all retained and readable.

**What `LC` also exposes.** The one-level list of the container by the `LC` holder returned 1000 entries then
`sizeLimitExceeded` (the lab's accumulated deleted objects): *every* deleted object of the domain, of every class,
privileged ones included, is enumerable (name, DN, GUID), and each object's attributes are readable exactly as far as
its retained descriptor lets that identity read (for ordinary users that is the same as the live read). The right
cannot be scoped to an OU or a class, and each domain has its own container (a child domain needs its own grant).

## The R2 read set on Windows (deleted user, Recycle Bin on)

| Attribute | Returned to the `LC` holder? | Note |
| --- | --- | --- |
| `objectSid`, `primaryGroupID`, `userAccountControl` (512, i.e. **not** disabled), `adminCount`, `msDS-AllowedToDelegateTo`, `lastKnownParent`, `msDS-LastKnownRDN`, `isDeleted`, `nTSecurityDescriptor` (owner+group+DACL, 2472 bytes) | yes | `userAccountControl` retained: answers the `[UNVERIFIED Windows]` in §8.10.3 kind 6 for the delete side; what the **restore** does to it is still untested |
| **`memberOf`** | **empty unless the request also carries `LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID` `1.2.840.113556.1.4.2065`**; with it, returned (also for the `LC` holder and for a Domain Admin) | **Correction to the contract:** §8.10.3 kind 6 says link values are retained and lists `memberOf` in the read set, but names the control only for group `member` reads. Step 7 must send 2065 on the target read, or every retained membership looks like none and C2 passes by absence |
| `isRecycled` | absent (correct for a Recycle-Bin-deleted, not-yet-recycled object) | present only after `msDS-deletedObjectLifetime` |
| SACL | not returned (flag 8 yielded no value) | consistent with the identity holding no SeSecurity |
| `sIDHistory`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-SecondaryKrbTgtNumber`, `isCriticalSystemObject` | **not tested**: the lab objects had none set. `[UNVERIFIED Windows]` retention | CC-WK-16 W should set each before the delete and diff |

## Reading the group side needs no container grant (and answers only C2)

A plain user reading a **live** group's `member` with 2065 sees the deleted members as
`CN=<name>\0ADEL:<guid>,CN=Deleted Objects,…` (all 4 victims, no container grant). So "is this deleted object still
a member of a `tier0` group?" can be answered from the groups. It cannot supply `objectSid` (C1 by RID), UAC (C5),
delegation (C12), the descriptor (C17/C18) or `adminCount`, and it needs a scan of every group in the connector's
set, not a read of the target. It is a partial cross-check, **not a replacement** for step 7.

## Operational notes on granting `LC` (if the decision is to ship)

- By default no non-administrator ACE exists; only SYSTEM can write the container. The KB procedure is
  `dsacls "CN=Deleted Objects,…" /takeownership` (owner becomes Domain Admins), then `/G <principal>:LC`. That leaves
  the owner changed. **Measured:** an Administrator can put the owner back to SYSTEM by writing owner+DACL
  (SD_FLAGS 0x05) with the descriptor above; the container then reads exactly as found. Keeping an `LC` ACE with the
  owner restored was not run `[UNVERIFIED]` (the write path is the same).
- `dsacls /setowner` is not an option; the owner reset needs a descriptor write.
- Existing-grant checks (Plan `MISSING_RIGHT`): the right to test is `LC` on the container of the *target's* domain;
  "no `LC`" must surface as a named missing right, not as `OBJECT_NOT_FOUND`, because the read gives `noSuchObject`
  either way. A restore *write* by the Reanimate identity still works with no `LC` (T-0076), so a technician can
  restore without a classified step 7 only by bypassing the gate: the build must not allow that path.

## Options for the decision (T-1730; AD facts only, the call is security-architect's)

1. **Ship kind 6 with a documented optional prerequisite:** `LC` on `CN=Deleted Objects` of each managed domain for the
   classification identity only. R15's stated worry (a *standing, network-reachable credential that can read every
   deleted object*) is true for this identity, bounded by the retained descriptors; the identity already reads the
   live objects. Amend R15/TM-D31 (they were written for the Recently Deleted report, which stays unbuilt) and
   §8.10.9 R2. Plan refuses `INSUFFICIENT_RIGHTS` ("List Contents on Deleted Objects") when absent.
2. **Do not ship kind 6 in v1.** Keep restore as a Tier-1 manual procedure. Clean, but loses ADM-038's restore.
3. **Classify on server-supplied data (activeDIQ inventory) plus the group-side cross-check.** R2 forbids it, and the
   inventory can be stale (a group added since the last sync); listed only for completeness.
4. **Restore into a quarantine OU and classify the live object, then move.** Does not work as a gate: the undelete
   reactivates every retained group link at once, so a retained `tier0` membership is already re-granted before the
   check. (Reasoned, not run.)

## Lab reality

- Verified on **Windows Server 2025** only. Samba's deleted-object visibility rules differ (the
  [CVE-2018-14628](https://www.samba.org/samba/security/CVE-2018-14628.html) fix changed what non-administrators can
  see), the T-1628 run did not read as a non-administrator, and Samba keeps ghost `member` values for deleted users.
  **A Samba test of step 7 can false-pass or false-fail; the grant requirement must be tested on Windows
  (conformance CC-WK-16 W).**
- Single DC, single domain, Recycle Bin on. Not run: a child domain's own container, a non-default `dSHeuristics`
  beyond the list-object probe, a pre-Recycle-Bin tombstone, inheritance of the container ACE to new deleted objects
  (not needed: `LC` is on the container itself).
- Lab left as found: container descriptor identical to the default (re-read), `dSHeuristics` unchanged, OU, test
  accounts, group and root ACE removed. Deleted `t1633-*` users remain in `CN=Deleted Objects` until they expire.

## Sources

- [KB 892806, let nonadministrators view deleted objects](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/non-administrators-view-deleted-object-container)
- [LDAP_SERVER_SHOW_DELETED_OID](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-show-deleted-oid)
- [ADS_RIGHTS_ENUM](https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum)
- [MS-ADTS 3.1.1.3.4.1.25, show deactivated link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/059e33fc-c7af-451e-92a9-fcb33d828f0f)
- [T-0076 lab confirmation](../runbooks/windows-lab-runs/T-0076-ad-lab-confirmation-20261028.md) · [T-1633 log](../runbooks/windows-lab-runs/T-1633-deleted-object-read-20261107.log.txt) · [driver source](../runbooks/windows-lab-runs/T-1633-driver-source.py.txt)
- Contract and TM: [connector-contract §8.10.3 kind 6, §8.10.9 R2](../architecture/connector-contract.md) · [threat-model §6.3 R9, R15](../architecture/threat-model.md)
