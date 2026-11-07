---
title: "Reading a deleted object: what the classification identity needs (restore step 7)"
date: 2026-11-07
updated: 2026-11-07
status: draft
amended_by: T-1734 (Windows lab: grant mechanics, items 1-6)
owner: heramb
author: ad-expert
ticket: T-1633
follow_up: T-1734
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

## T-1734: the grant mechanics, measured on Windows Server 2025 (conclusion first)

**TM-D33 stands. Items 1, 2, 3, 5 and 6 pass; item 4 passes for RBCD and the computer `isCriticalSystemObject` flag and stays
`[UNVERIFIED Windows]` for `sIDHistory` (Windows refuses to let anyone write it over LDAP, so the lab cannot make the test
object). Items 5 and 6, the TM-D33 rule 7 triggers, did not fire: a deleted object was never more readable than the live one,
and a confidential attribute on a deleted computer still needs Control Access.** Raw log:
[T-1734 log](../runbooks/windows-lab-runs/T-1734-deleted-objects-grant-20261107.log.txt) · [driver source](../runbooks/windows-lab-runs/T-1734-driver-source.py.txt).
Lab: dc1, build 26100, forest and domain level 2025, Recycle Bin on, single DC. Reader identities were ordinary users; the
grant was applied to a domain-local group exactly as TM-D33 rule 1 says (the ACE trustee is the group, the user is a member).

| # | Question | Result (dc1) |
| --- | --- | --- |
| 1 | Does the `LC`\|`RC` ACE survive the owner reset to SYSTEM (SD_FLAGS 0x5)? | **Yes**, in both write orders. (A) take ownership, then one 0x5 write carrying the ACE and owner SYSTEM; (B) take ownership, DACL-only write (0x4) with the ACE, then a separate owner-only write (0x1) to SYSTEM. Read back as the grantee: `O:SYD:PAI(A;;LCRC;;;<group>)(A;;LCRP;;;BA)(A;;KA;;;SY)`, mask 0x20004, **no inheritance flags**, protected flag (`P`) kept, unchanged after 10 s. The `dsacls /takeownership` + `/G <group>:LC` path (KB 892806) also kept its ACE through the typed 0x5 reset (the DACL as read by Domain Admin, owner DA); its post-reset survival was not read back because an LC-only grantee cannot read the descriptor, so the direct proof is A and B |
| 2 | With `RC` + show-deleted, can a non-admin read the container's owner+DACL by its WKGUID? | **Yes.** `<WKGUID=18e2ea80684f11d2b9aa00c04f79f805,DC=…>` (and the plain DN) with the show-deleted control and SD_FLAGS 0x5 or 0x7 returns `nTSecurityDescriptor`. The connection identity first resolves the DN from the domain head's `wellKnownObjects` (`B:32:18E2EA80…:CN=Deleted Objects,DC=…`), which any authenticated user can read. Details and four negative controls below |
| 3 | Must-be-present R2 set per class | **Complete for group, computer, contact and OU** (user as control): `objectGUID`, `isDeleted`, `lastKnownParent`, `msDS-LastKnownRDN`, `nTSecurityDescriptor` came back for all five classes; `objectSid` for user, computer, group; `userAccountControl` (computer 4096, user 512) and `primaryGroupID` for user and computer. Contact and OU have no `objectSid`/UAC, and the contract does not ask for them. The contract's per-class table is right as written; the "measured for a deleted user only" caveat can go |
| 4 | Retention | RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`, 80 bytes) **retained and readable** on a deleted computer and a deleted user. `isCriticalSystemObject`: a computer carries **FALSE**, retained and readable after delete; a user has none. `sIDHistory` and `msDS-SecondaryKrbTgtNumber`: **not measured** (below) |
| 5 | Inherited deny on the OU before deletion | **Still applies.** The deleted child's descriptor is **byte-identical** to its live descriptor (2436 bytes, 51 ACEs, the inherited deny ACE type 1, flags 0x12, mask `RC`\|`RP` present): the DC does not recompute inheritance when it moves the object into the container. The grantee's read of the deleted child returns exactly what its read of the live child returned |
| 6 | Confidential attribute on a deleted computer | **Still needs Control Access.** `msLAPS-Password` (searchFlags 904 = confidential + preserve-on-delete + never-audit + RODC-filtered) and `unixUserPassword` (searchFlags 128): the `LC`\|`RC` holder with ordinary read rights gets the computer entry **without** the attribute, deleted or live; an identity with inheritable Read Property + Control Access on the OU (set before the delete) gets the value on the deleted computer exactly as on the live one; Domain Admin gets it. Same answer live and deleted for all three |

### Item 1 and 2: facts the wizard and VerifyConnection must be built on

- **The default container descriptor is unreadable to everyone but SYSTEM, Domain Admin included.** Before any change, an
  Administrator's base read (show-deleted, SD_FLAGS 0x7) returns the entry with **zero `nTSecurityDescriptor` values**, and
  `dsacls "CN=Deleted Objects,…"` answers "Insufficient access rights". The default DACL gives Administrators `LCRP` but not
  Read Control, and only the owner holds implicit Read Control. After *taking ownership* the same read returns 112 bytes:
  `O:DAG:SYD:PAI(A;;LCRP;;;BA)(A;;KA;;;SY)` (the order the DC stores; .NET's SDDL rendering swaps the two ACEs, which fooled
  the first comparison in the log). Consequences: a hardening plan cannot show the as-found DACL before its first write (step 1
  is the owner write); once the owner is SYSTEM again nobody but a holder of `RC` can read the descriptor, so **the connection
  identity's `RC` is the only way anyone, including the customer's Domain Admin, can verify the grant afterwards** without
  re-taking ownership. That is the reason `RC` is in the ACE and it is now measured, not assumed.
- **Take ownership with a typed owner-only write.** A Domain Admin's modify of `nTSecurityDescriptor` with SD_FLAGS 0x1 and a
  descriptor that carries only the owner (Domain Admins) is accepted over LDAPS (no `dsacls` needed). `SeTakeOwnership` is
  enough; `dsacls /takeownership` also works.
- **Removal also needs the takeover.** Writing the baseline (owner SYSTEM, original DACL, 0x5) straight away as Domain Admin with
  the owner still SYSTEM is refused, `insufficientAccessRights`; after the owner-only takeover the same write succeeds and the
  container reads exactly as found (three runs). The removal plan has the same shape as the apply plan, as TM-D33 rule 2 says.
- **Reading the descriptor, by identity** (SD_FLAGS 0x5 or 0x7, show-deleted, base scope, by WKGUID or DN):

  | Identity holds on the container | Result |
  | --- | --- |
  | `LC`+`RC` | descriptor returned |
  | `RC` only | descriptor returned (so *reading* needs only `RC`; *using* the container needs `LC`) |
  | `LC` only | entry returned, **no descriptor value**, no error |
  | nothing | entry returned, no descriptor value, no error |
  | any of the above, show-deleted control left off | `32 noSuchObject` (the container is itself `isDeleted`) |
  | `LC`+`RC`, SD_FLAGS includes the SACL bit (0x8 or 0xF) | entry returned, **no descriptor value, no error** |

  So "descriptor unreadable" is an *entry with no attribute*, never an error, and it is indistinguishable between "no RC" and
  "SACL bit requested": the connector must request exactly 0x5 (never 0x8, never 0xF) or it will report a granted identity as
  ungranted. Treat entry-without-descriptor as `INSUFFICIENT_RIGHTS`, as TM-D33 rule 4 already says.

### Item 3: the optional set on the other classes

Computer: `memberOf` (with control 2065), `isCriticalSystemObject` (FALSE) and, when set, RBCD came back. Group: `memberOf` came
back. Contact and OU: none of the optional set exists. All as the `LC`|`RC` holder, default retained descriptors. A computer
gets `isCriticalSystemObject` FALSE from SAM at creation; a user has no value, live or deleted, so for a user "absent" is the
ordinary state and only the retained-descriptor proof in contract step 7.3 can turn it into "not set".

### Item 4: what could not be measured, and why

- **`sIDHistory`**: a Domain Admin's LDAP write is refused ("Access is denied"); it can only be created by the SID-history
  migration API from a *different* source domain. dc2 and any trust are human-only (windows-lab.md §10), so no worker can
  produce a deleted object with the value. Schema, measured: searchFlags 1 (indexed), systemFlags 0x12 (global-catalog member),
  not preserve-on-delete. **That flag does not decide retention while the object is merely deleted:** RBCD has searchFlags 0 and
  was retained. The rule that applies is MS-ADTS's "deleted-objects maintain virtually all of their state" when the Recycle Bin is
  on ([MS-ADTS Recycle Bin](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9482178-ee53-4b6c-841d-5259d6261985)).
  It stays `[UNVERIFIED Windows]` for `sIDHistory`; the design is not weakened, because an absent optional attribute is already
  `tier0` unless the retained descriptor proves it readable.
- **`msDS-SecondaryKrbTgtNumber`**: write refused ("owned by the system"; it belongs to RODC krbtgt accounts). Not measured.
- **`isCriticalSystemObject` TRUE**: cannot be written by anyone over LDAP ("owned by the Security Accounts Manager"), so a
  deletable ordinary object cannot carry TRUE; the only TRUE objects are built-in and DC accounts, which the lab must not delete.
  Not measured. The FALSE retention on computers is measured.

### Item 5 and 6 in detail

- **Setup (item 5).** `dsacls <OU> /I:S /D "<cls>:RPRC"` wrote an inherit-only container ACE; the user child inherited it as
  type 1, flags 0x12 (`INHERITED_ACE`|`CONTAINER_INHERIT`). **An inherited deny sorts after the explicit allows in the user's
  default DACL**, so it hides only what no earlier explicit allow covers: the grantee's live read lost `userAccountControl`,
  `adminCount`; after the delete it also lacked `isDeleted`, `lastKnownParent`, `msDS-LastKnownRDN` (which an unblocked sibling
  returns). `objectSid`, `primaryGroupID`, `description` stayed readable under the deny. Two consequences for the connector:
  the must-be-present set can be incomplete while `objectSid` is present, so **one present attribute never means the rest are
  readable** (contract step 7.3 already refuses on any absent must-be-present attribute); and a property-level inherited deny on
  `userAccountControl` alone hid exactly that attribute on the live and the deleted child, nothing else.
- **The retained descriptor is identical** (P4 in the log: raw bytes equal, 51 ACEs). This matches T-1633's explicit-deny result
  (zero attributes returned) and extends it to inherited ACEs.
- **Item 6.** The attribute was present on the object (Domain Admin and the Control-Access identity read it, canary matched), so the
  grantee's missing value is the Control Access check, not a missing value. The lab forest did **not** have the Windows LAPS
  schema (`msLAPS-*` absent although the forest is level 2025 and the doc says
  [`msLAPS-CurrentPasswordVersion` ships with the first 2025 DC](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference);
  it was absent here too). **This ticket ran `Update-LapsADSchema` on dc1: an irreversible schema extension of the lab forest**
  (7 attributes, the `ms-LAPS-Encrypted-Password-Attributes` extended right, `mayContain` on `computer`); any later LAPS test
  on dc1 starts from it. `msLAPS-EncryptedPassword` (security GUID = that extended right), BitLocker recovery information (a *child*
  object of the computer, needing a subtree delete) and legacy `ms-Mcs-AdmPwd` (schema absent) were not run; they use the same
  confidentiality mechanism (searchFlags bit 0x80) and are covered by the same rule.

### What changes in the contract and the threat model (done in this ticket)

Tags cleared with this evidence: TM-D33 rule 2 (ACE survives the reset), TM-R28 (confidential attributes), TM §6.3 R15 (b) (`RC`
sufficiency), connector-contract §8.10.3 kind 6 step 1 (Read Control plus show-deleted returns the descriptor) and the "measured for
a deleted user only" caveat of step 3. Additions the owners should carry: (1) request SD_FLAGS exactly 0x5 for the container; an
entry without the attribute is `INSUFFICIENT_RIGHTS`; (2) the hardening plan's first step is the owner write, and it cannot display
the as-found DACL before it; the removal plan needs the takeover too; (3) `sIDHistory` retention stays `[UNVERIFIED Windows]`.
Tests on Samba would give a false pass for all of this (Samba's deleted-object visibility and descriptor rules differ).

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
  (SD_FLAGS 0x05) with the descriptor above; the container then reads exactly as found (T-1734 repeated it three times and also showed the Domain Admin cannot even *read* the default descriptor without taking ownership first). Keeping an `LC`|`RC` ACE with the
  owner restored **was run in T-1734** and the ACE survives (above).
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
