---
title: "Safe primitive P6: the typed security-descriptor model (MS-DTYP SD/ACL), SD_FLAGS and diff-based DACL edits"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
ticket: T-0028
sources_last_checked: 2026-10-02
---

# P6 — `sd`: typed security descriptors

Sibling of `safe-primitives.md` (T-0005). CLAUDE.md rule 5 names security descriptors as a safe-primitive
class; T-0005 left them out. This document is the P6 spec, and it follows the rules R1–R9 of
`safe-primitives.md` §1 (typed in/out, reject-never-repair, bounded, one corpus). It is what T-0118
(read path) and a later write-path ticket (§11) build, and what T-0053 consumes.

**Why a primitive.** An SD is a binary structure with offsets, counts and sizes. Whoever hand-slices it,
or round-trips it through SDDL text, gets one of: a parser that disagrees with the DC about where an ACE
ends; a DACL written with a dropped owner or SACL; an ACE order that flips a deny into a no-op; or an
SDDL alias (`DA`) that silently means a *different domain's* Domain Admins. ManageEngine-class tools are
judged on exactly these (feasibility `build-feasibility/ad-technical-feasibility.md` §2.7, "SDDL / ACL
corruption" row). The unsafe call is made unrepresentable.

| # | Primitive | Bans | Tiers | Implementer |
| --- | --- | --- | --- | --- |
| P6 | `sd`: SD/ACL/ACE decoder and encoder, `SDFlags` control encoder, effective-rights helper, `DACLWrite` builder (write half), `SDDLDisplay` renderer | slicing `nTSecurityDescriptor` bytes; SDDL parsing or building; whole-SD writes; ACE edits by position | S, A (same package; tier A for NTFS/share SDs later). N, X, W: none. W shows the server's ACE rows (as in `safe-primitives.md` §2.1) | directory-engineer |

**Verification vocabulary** (ticket AC 2). Every behaviour below carries a tag: **doc** = stated in
Microsoft documentation, never run; **Samba** / **Windows** = observed in the lab (none yet); **doc+blog** = only a secondary source; `[UNVERIFIED]` = nobody has confirmed it. As of
2026-10-02 **nothing here is lab-verified**. §9 lists, per behaviour, where it must be verified and
where a Samba pass would be a false pass.

---

## 1. The model an AD admin expects

Self-relative SD (the only form on the LDAP wire; little-endian, no padding) —
[MS-DTYP 2.4.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d) (doc):

| Field | Rule |
| --- | --- |
| `Revision` (1 B) | MUST be 1 |
| `Sbz1` (1 B) | resource-manager bits only if Control `RM` is set; else ignore (preserve) |
| `Control` (2 B) | `SR` 0x8000 (MUST be set on the wire), `RM` 0x4000, `PS` 0x2000 (SACL protected), **`PD` 0x1000 (DACL protected)**, `SI` 0x0800, **`DI` 0x0400 (DACL auto-inherited)**, `SC` 0x0200, `DC` 0x0100, `SS` 0x0080, `DT` 0x0040, `SD` 0x0020, `SP` 0x0010 (SACL present), `DD` 0x0008, **`DP` 0x0004 (DACL present)**, `GD` 0x0002, `OD` 0x0001 |
| `OffsetOwner/Group/Sacl/Dacl` (4 B each) | 0 ⇒ component absent. Offset must be valid when the matching flag is set (`SP`, `DP`; owner/group unless defaulted). Components may appear in any order |
| Owner/Group SID | length is a multiple of 4 |

Bit values are derived from the order of the MS-DTYP diagram (`SR` is bit 15 … `OD` is bit 0) and agree with the Win32
[security descriptor control](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control) constants (`SE_DACL_PRESENT` 0x4,
`SE_DACL_PROTECTED` 0x1000, `SE_DACL_AUTO_INHERITED` 0x400, `SE_SACL_PRESENT` 0x10, `SE_SELF_RELATIVE` 0x8000); SD-01 pins them in the corpus.

**ACL** — [MS-DTYP 2.4.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428) (doc).
Header: `AclRevision` (1), `Sbz1` (1, must be 0), `AclSize` (2, whole ACL incl. ACEs), `AceCount` (2), `Sbz2` (2, must be 0).
Only revisions **2** and **4** are valid on the wire. Revision 2 allows ACE types 0x00–0x03, 0x11–0x13; revision 4 additionally
allows the object types 0x05–0x08 (and 0x11). Parsing "MUST be computed by using AclSize and AceCount".
Three distinct DACL states, and they mean opposite things:

| State | Wire | Meaning |
| --- | --- | --- |
| **absent** | `DP` clear, `OffsetDacl` 0 | no DACL in this SD (for AD object creation: the default/inherited DACL applies, see §3) |
| **empty** | `DP` set, ACL with `AceCount` 0 | **nobody** gets access (owner keeps implicit READ_CONTROL/WRITE_DAC) |
| **NULL** | `DP` set, `OffsetDacl` 0 `[UNVERIFIED on the AD wire]` | **everyone** gets full access. [Win32: "no DACL … allows everyone full access"](https://learn.microsoft.com/en-us/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects) (doc, creation context). MS-DTYP says the offset "must be valid if DP is set", so a NULL DACL may never appear in AD reads; the decoder still surfaces it as its own state, never as empty |

**ACE** — [ACE_HEADER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586) (doc):
`AceType` (1), `AceFlags` (1), `AceSize` (2, **multiple of 4**, may exceed the sum of the fields).

| Type | Hex | In DACL | Notes |
| --- | --- | --- | --- |
| ACCESS_ALLOWED / ACCESS_DENIED | 0x00 / 0x01 | yes | simple ACE: Mask(4) + SID |
| ACCESS_ALLOWED_OBJECT / DENIED_OBJECT | 0x05 / 0x06 | yes (**ACL rev 4**) | adds `Flags`(4), optional `ObjectType`(16), optional `InheritedObjectType`(16) |
| ALLOWED/DENIED_CALLBACK (+_OBJECT) | 0x09, 0x0A, 0x0B, 0x0C | yes | conditional (claims) ACEs; trailing application data. Not used by AD DS in v1 scope: decoded, never evaluated |
| SYSTEM_AUDIT / _OBJECT / _CALLBACK / _CALLBACK_OBJECT | 0x02, 0x07, 0x0D, 0x0F | **SACL only** | |
| MANDATORY_LABEL, RESOURCE_ATTRIBUTE, SCOPED_POLICY_ID | 0x11, 0x12, 0x13 | SACL only | |
| ALARM, COMPOUND (reserved) | 0x03, 0x04, 0x08, 0x0E, 0x10 | — | "Reserved for future use": opaque |

"The SACL MUST NOT contain ACEs that belong in the DACL, and the DACL MUST NOT contain ACE types that belong in the SACL.
Doing so results in unspecified behavior" (MS-DTYP 2.4.5) — so we treat it as hostile, not as something to interpret.

`AceFlags` (doc): OBJECT_INHERIT 0x01, CONTAINER_INHERIT 0x02, NO_PROPAGATE_INHERIT 0x04, INHERIT_ONLY 0x08,
**INHERITED 0x10**, SUCCESSFUL_ACCESS 0x40, FAILED_ACCESS 0x80 (audit ACEs only). Win32 also defines CRITICAL_ACE_FLAG 0x20, which MS-DTYP's table omits; any other bit is treated as unknown (anomaly `ace.unknown_flags`).

**Object ACE layout** — [MS-DTYP 2.4.4.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe) and the
[Win32 structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace) (doc):
`Flags` bit 0x1 = `ObjectType` present, 0x2 = `InheritedObjectType` present. **An absent GUID is not present in the
bytes at all**: the SID starts right after `Flags` (Flags 0), after `ObjectType` (Flags 1) or after
`InheritedObjectType` (Flags 2). Trap: a fixed-offset parser reads the SID from the wrong place for every ACE that does not carry both GUIDs. GUIDs
are in the same mixed-endian layout as `objectGUID` (P3 `attr.guid`).
`ObjectType` meaning depends on the Mask bit (MS-ADTS
[access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584), doc):

| Mask bit | Value | `ObjectType` names |
| --- | --- | --- |
| CREATE_CHILD / DELETE_CHILD | 0x1 / 0x2 | an `objectClass` `schemaIDGUID`; absent ⇒ all classes |
| LIST_CONTENTS | 0x4 | — |
| SELF (validated write) | 0x8 | a validated-write right GUID; absent ⇒ all |
| READ_PROP / WRITE_PROP | 0x10 / 0x20 | an attribute `schemaIDGUID` or a property set; absent ⇒ **all attributes** |
| DELETE_TREE / LIST_OBJECT | 0x40 / 0x80 | — (LIST_OBJECT is only enforced when `dSHeuristics` fDoListObject is TRUE) |
| CONTROL_ACCESS | 0x100 | a control-access right `rightsGUID`; absent ⇒ **all** extended rights (including Reset Password) |
| DELETE / READ_CONTROL / WRITE_DAC / WRITE_OWNER | 0x10000 / 0x20000 / 0x40000 / 0x80000 | — |

"ACCESS_MASK bits are not mutually exclusive … If the AccessCheck algorithm … does not find an appropriate GUID, then that ACE will be ignored"
(MS-DTYP 2.4.4.3): an object ACE whose GUID does not match its mask bit is **valid and inert**, which is why the builder checks (§5, SD-E06).
`InheritedObjectType` limits which child *classes* receive the ACE at inheritance time; absent ⇒ all classes.
**Generic bits (GR 0x80000000, GW 0x40000000, GX 0x20000000, GA 0x10000000) are never stored in AD**: they are mapped on write
to GR=RC|LC|RP|LO, GW=RC|WP|VW, GX=RC|LC, GA=DE|RC|WD|WO|CC|DC|DT|RP|WP|LC|LO|CR|VW. Other bits are "ignored in Active Directory DACLs" (doc, same page).
A server-returned DACL therefore never contains generic bits, and a client that wrote GA and expects to read GA back sees different bytes.

**Canonical order** — MS-DTYP 2.4.5 (doc), the five rules: (1) all explicit ACEs before inherited ACEs; (2) within explicit, deny before allow;
(3) deny ACEs on the object before deny ACEs on a child or property; (4) the same for allow; (5) inherited ACEs in the order inherited
(parent's first, then grandparent's; deny before allow at each level, per the
[Win32 order page](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl)). "On the object" = an ACE with no `ObjectType`;
"on a child or property" = an object ACE with `ObjectType`. The DC evaluates **in stored order** until it finds a decision
([MS-ADTS 5.1.3.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2f146d9e-393d-4c90-a9c7-780b73884a60), doc), so a non-canonical DACL
changes who has access; "canonicalising" it is a semantic edit, never a tidy-up.
Whether the DC rejects or reorders a non-canonical DACL on an LDAP modify is `[UNVERIFIED]` (Windows and Samba).

**SD_FLAGS control** `1.2.840.113556.1.4.801` — [MS-ADTS 3.1.1.3.4.1.11](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0)
and [6.1.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499) (doc):
value = BER `SEQUENCE { Flags INTEGER }`; OWNER 0x1, GROUP 0x2, DACL 0x4, SACL 0x8; other bits ignored by the server.
- **No bits set, or no control at all, means 15 (all four, SACL included) — not "nothing".** The default is not the safe value.
- Search: the SD comes back only if `nTSecurityDescriptor` is named, or the attribute list is empty/`*` *and the control is present*. Without the control, only an explicit name returns it.
- Modify: "the server only updates the fields that are identified by the SD control. The remaining fields are ignored", even if the client supplied them. On Add the control "will be ignored".
- The control adds no response control.
- Read of the SACL needs `SeSecurityPrivilege`; for a modify that writes the SACL the spec states it as a requirement ([6.1.3.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7afacb02-548b-4e74-bf96-04b0bf0c71b6), doc). What a *search* returns to a caller who lacks the privilege and asked for flags 15 or 8 is `[UNVERIFIED]` for AD: the Win32 API family returns only the DACL ([doc, secondary: general Win32 behaviour](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditqueryglobalsacla)), but nothing I found documents the LDAP result. The primitive never relies on either outcome (SD-R3).
- `sDRightsEffective` (constructed, `1.2.840.113556.1.4.1304`): bits OWNER (1, covers owner **and** group), DACL (4), SACL (8) say which parts the caller can write (doc+secondary: [Win32 AD schema](https://dotnet.territoriali.olinfo.it/sv-se/windows/win32/ADSchema/a-sdrightseffective) mirror; the MS-ADA3 page was not fetched in this pass). It is the preflight for a write.

**Write authorization** — MS-ADTS 6.1.3.5 (doc). DACL write: explicit WRITE_DAC, **or** the new SD's OWNER is in the requester's token
(implicit owner rights). Owner/group write: WRITE_OWNER, or SeTakeOwnershipPrivilege, or the DS-Set-Owner control right on the NC root; the new
owner must be the caller, the Default Administrators group (if member), or any SID with SeRestorePrivilege — else `unwillingToPerform` / `ERROR_INVALID_OWNER`.
Since the [CVE-2021-42291 updates](https://support.microsoft.com/en-au/servicing/os/windows-server/2021/11/kb5008383-active-directory-permissions-updates-cve-2021-42291)
(and Windows 11 22H2+), **implicit owner rights are blocked** for non-Domain/Enterprise Admins on `computer` objects when the
`BlockOwnerImplicitRights` dsHeuristic is on ([MS-ADTS 6.1.3.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c); on Windows 11 26H1 the rule set changes again). Version dependent: results differ per DC patch level.

---

## 2. Types and API sketch (neutral pseudo-signatures; Go names illustrate ADR-0001)

```text
package sd

type Parts uint8              // Owner=1 Group=2 DACL=4 SACL=8; the 4 bits and nothing else
type SACLCap struct{ ... }    // unforgeable capability, issued only to a Tier-0 connector identity (feasibility §2.7 "SACLs are Tier-0")

// --- read half (T-0118) ------------------------------------------------------
type Raw []byte                                  // what the connector returns for nTSecurityDescriptor; opaque outside sd+connector
func Decode(r Raw) (SD, error)                   // strict; typed errors; never panics; bounded (MaxSDBytes)
type SD struct {                                 // immutable value
    Owner, Group SID (optional)                  // P3 attr.sid types
    DACL, SACL   ACLState                        // Absent | Null | List{Revision, ACEs}
    Control      Control                         // raw 16 bits + named accessors (Protected(), AutoInherited() ...)
    RMBits       uint8
    Anomalies    []Anomaly                       // non-fatal oddities, see §4; non-empty ⇒ not editable
}
type ACE struct {                                // sum type; one of:
    Basic{Type, Flags, Mask, Trustee SID}
    Object{Type, Flags, Mask, Trustee SID, ObjectType *GUID, InheritedObjectType *GUID}
    Callback{...}                                // decoded, not evaluated
    Opaque{Type, Flags, Bytes}                   // unknown/reserved/misplaced type: preserved byte-for-byte, never interpreted
}
func (a ACL) IsCanonical() CanonicalReport       // which of the five rules fails, and at which index
func (s SD) ACEs() []ACEView                     // each with Index, Inherited bool, EffectiveOnObject bool (=!INHERIT_ONLY)

func ReadControl(p Parts, c ...SACLCap) (Control, error)   // BER 30 03 02 01 <p>; error on p==0, unknown bits, SACL without cap
func Grants(p Principal, right Right, o ObjectCtx, s SD) Decision
// Decision: Yes | No | Unknown, plus []Source{ACEIndex, Inherited, ObjectType, Reason}; Unknown carries why
type Principal struct{ SIDs SIDSet; SelfSID *SID }   // user SID + tokenGroups (incl. primary group); built by the caller from the DC, never from names
type Right struct{ Mask Mask; Object *GUID; Kind RightKind }   // Kind: Class | Attribute | PropertySet | ControlAccess | ValidatedWrite | Whole

// --- display only ------------------------------------------------------------
func (s SD) DisplaySDDL() SDDLDisplay            // output only; there is no inverse function anywhere

// --- write half (later ticket, §11) -----------------------------------------
type RightsCatalog interface{ Kind(g GUID) (RightKind, bool) }     // from the schema cache; never from a literal table
type ACEDiff struct{ Add []NewACE; Remove []ACERef }               // ACERef = {index, expected ACE digest}; both must match
func PlanDACL(base SD, d ACEDiff, cat RightsCatalog, o ObjectCtx, opt PlanOpts) (DACLWrite, Plan, error)
func PlanInheritance(base SD, op SetProtected|ClearProtected{KeepInherited bool}, ...) (DACLWrite, Plan, error)   // the ONLY way to change PD
type DACLWrite struct{ ... }   // opaque. Carries: object GUID, base-DACL digest, new DACL bytes, the control to send. Constructible only by Plan*.
func (w DACLWrite) Control() Control             // always Parts{DACL}, critical
func (w DACLWrite) Value() Raw                   // SD whose OffsetOwner=OffsetGroup=OffsetSacl=0, SP clear, DP set
```

Rules the sketch encodes:

- **SD-R1 Typed in, typed out.** `Raw` has no exported index/slice/convert outside `sd` and the connector. Nothing outside `sd` constructs a value for the attribute `nTSecurityDescriptor`; the connector's modify takes a `DACLWrite`, not bytes. Attribute names are LDAP case-insensitive, so the check is case-insensitive.
- **SD-R2 SIDs and GUIDs only.** ACE trustees are P3 `SID` values. There is no constructor from a name, an SDDL alias (`DA`, `BA`, `WD`) or an unchecked string. Names are resolved by the caller, displayed, never stored in the ACE type.
- **SD-R3 Read always names its parts.** A search that requests `nTSecurityDescriptor` (by name, `*` or empty list) always attaches `ReadControl(Parts)`, criticality **true**. The default parts are `OWNER|GROUP|DACL` (0x7). SACL only with `SACLCap`. A search that would return the SD without the control is refused by the connector (SD-C06). If the entry comes back **without** the attribute (no READ_CONTROL, or the control was dropped), the result is the typed error `sd.not_returned`, never an empty or default SD: "no ACEs" and "could not read" must not look alike to the Tier-0 guard (T-0053).
- **SD-R4 Writes are DACL-only, by construction.** `DACLWrite.Control()` is `Parts{DACL}` (`30 03 02 01 04`), critical, and `Value()` zeroes the other offsets even though the server ignores them (6.1.3.2). Critical so that a server that does not understand the control fails instead of treating the value as flags 15. No API writes owner, group or SACL in this revision (owner/group/SACL writes need their own spec; SACL is Tier-0).
- **SD-R5 Edits are diffs.** Callers state ACEs to add and ACEs to remove (identified by index **and** a digest of the ACE bytes, so a stale index cannot remove a different ACE). They never submit a whole DACL, and never submit a DACL built from another object's SD. The plan includes a before/after of the changed effective rights so the UI and audit can show what the edit does.
- **SD-R6 Inherited ACEs are read-only.** An ACE with INHERITED (0x10) cannot be removed or modified: the DC recomputes inheritance from the parent, so the edit is either overwritten or leaves an explicit duplicate. Change the grant on the parent, or use `PlanInheritance`. New ACEs must not carry INHERITED.
- **SD-R7 Inheritance flags are not editable by diff.** `PD` (protected) and `DI` (auto-inherited) are copied from the base SD unchanged. `PlanInheritance` is the only way to flip `PD`; it is a separate operation class for approvals, and "break inheritance, keep copies" and "break inheritance, remove inherited" are different, explicit options. Whether the DC keeps INHERITED markers when a client writes a DACL without `DI` is `[UNVERIFIED]` (Samba is known to strip `ACE_INHERITED` when `SEC_DESC_DACL_AUTO_INHERITED` is absent, per [this Samba/ixsystems note](https://jira.ixsystems.com/browse/NAS-109277), doc+blog; Windows unknown), hence "copy, don't compute".
- **SD-R8 Canonical order on output, never silent reorder of input.** `PlanDACL` inserts new ACEs at the canonical position (key: inherited?, deny before allow, whole-object before object-scoped; stable within a class) and leaves the existing ACE order untouched. If the *base* DACL is non-canonical it returns `sd.base_non_canonical`; the caller may pass `Normalize` explicitly, which reports the effective-rights change the reorder causes, and is audited as its own action.
- **SD-R9 Anomalies make a DACL viewable, not editable.** See §4.
- **SD-R10 Verify after write.** After the modify the connector re-reads the DACL and compares with the plan, tolerating only the documented server transformations. Mismatch ⇒ audit the actual state, raise `sd.write_diverged`, no automatic retry. There is no compare-and-swap on a single-valued attribute known to us: a concurrent writer between read and write is lost (last writer wins), so the base-digest check (`sd.stale_base`) immediately before the write narrows the window but does not close it. A delete-old-value/add-new-value modify as an atomic compare is **`[UNVERIFIED]`**: test on Windows before relying on it.
- **SD-R11 Effective-rights helper is three-valued and conservative.** Inputs are SID sets from the DC (`tokenGroups` + user SID; `tokenGroups` includes the primary group), never names. Evaluation is in **stored ACE order**, skipping INHERIT_ONLY ACEs for the object itself, object ACEs whose `ObjectType` does not match the asked right, and ACEs whose trustee is not in the set; first match decides per bit. `InheritedObjectType` is ignored at evaluation (it only gates propagation; whether an inherited copy keeps the GUID is `[UNVERIFIED]`). `Unknown` for: callback ACEs, `SELF` (S-1-5-10) without a `SelfSID`, owner-implicit rights when an OWNER RIGHTS ACE or the block-implicit-rights heuristic may apply, mandatory-label/claims. **Consumers that guard (T-0053) treat `Unknown` as `Yes`.** NULL DACL ⇒ Yes for every bit; empty DACL ⇒ No (plus implicit owner READ_CONTROL/WRITE_DAC ⇒ Unknown/Yes for those two). The DC's own answers (`allowedAttributesEffective`, `allowedChildClassesEffective`, `sDRightsEffective`, a bind as the identity) remain authoritative for *the connector's own* rights; the helper exists for third parties and for "who can do what" reports, and reports must show the source ACE so an admin can disprove it in ADUC's Effective Access in thirty seconds (feasibility row: "Must match Windows 'Effective Access'").

### Constants (provisional until load tests; R5)

`MaxSDBytes` 256 KiB (two 64 KiB ACLs + SIDs cannot exceed ~131 KiB); `MaxACEsPerACL` = ⌊(AclSize−8)/16⌋ ≤ 4095 (smallest valid ACE is 16 bytes: 8 header+mask, 8 for an empty-subauthority SID); `MaxSubAuthorities` 15.

---

## 3. AD behaviours that shape the design

- **Where SDs live.** Every AD object has `nTSecurityDescriptor`; ACEs inherit down the tree; `defaultSecurityDescriptor` on a class is an **SDDL string** in the schema (not binary) and is merged on object creation ([Win32](https://learn.microsoft.com/en-us/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects), doc). Some other attributes hold binary SDs (RBCD `msDS-AllowedToActOnBehalfOfOtherIdentity`, gMSA `msDS-GroupMSAMembership`) `[UNVERIFIED: attribute pages not fetched in this pass]`. They use the same decoder (registry entry kind `sd`); their writes are out of this spec and need their own (SD_FLAGS may not apply to them).
- **Add vs modify.** On Add the DC merges inheritable parent ACEs into a supplied DACL unless `SE_DACL_PROTECTED` is set; with no SD supplied it merges them into the class default (doc, same Win32 page). The control is ignored on Add. This spec has no Add path.
- **AdminSDHolder / SDProp.** For protected accounts and groups the PDC emulator rewrites the DACL from `AdminSDHolder` about every 60 minutes and sets DACL-protected (doc+blog: [Microsoft Learn archive blog](https://learn.microsoft.com/pt-pt/archive/blogs/lrobins/admin-free-active-directory-and-windows-part-2-protected-accounts-and-groups-in-active-directory); the MS-ADTS page was not located in this pass `[UNVERIFIED: interval and default]`). An edit to such an object's DACL is silently reverted and, for the "inherited Reset-Password on protected users" case in T-0053, the grant is on the *parent OU* but does not reach protected users at all. `ObjectCtx.ProtectedBySDProp` is supplied by the caller from the computed protected set (never from `adminCount`, which goes stale); the write half refuses to plan a DACL edit on it (SD-E11).
- **Inheritance fan-out.** Editing a parent DACL makes the DC rewrite the SDs of descendants; each rewrite is a normal change (`uSNChanged`, replication, 5136-style events) `[UNVERIFIED]`. A sync or audit consumer should expect one parent edit to touch many children and must not treat the children as independent changes.
- **Owner and group.** AD ignores the primary group for access in DS context (Win32: "primary group is not used in the context of AD DS"); the decoder returns it, the helper ignores it.
- **NTFS and share SDs** (feasibility rows 133, 134, tier A) use the same wire structure: ACL rev 2 only, no object ACEs, file-system masks, different inheritance behaviour. `sd` models them with the same types; the mask-meaning tables (§1) are the AD ones, so file masks need their own `MaskKind` before any NTFS write is specified. Out of scope here.

---

## 4. Decode: errors versus anomalies

`Decode` returns an error (stable code, R6) for anything that makes the structure ambiguous or unsafe to walk. It returns an `SD` with `Anomalies` for oddities that are legal or that the DC may emit; an SD with anomalies is **viewable and not editable**, and the helper flags results derived from it.

| Errors (no SD returned) | Anomalies (SD returned, not editable) |
| --- | --- |
| `sd.truncated_header`, `sd.truncated`, `sd.too_large` | `acl.zero_slack` (all-zero bytes between the last ACE and `AclSize`) |
| `sd.bad_revision` (≠1), `sd.not_self_relative` (`SR` clear) | `ace.opaque` (unknown/reserved type, kept byte-for-byte) |
| `sd.offset_out_of_range`, `sd.components_overlap`, `sd.dacl_offset_without_flag`, `sd.sacl_offset_without_flag` | `ace.misplaced_type` (SACL-only type in DACL or the reverse) |
| `acl.bad_revision` (not 2/4), `acl.revision_type_mismatch` (object ACE in rev 2), `acl.size_out_of_range`, `acl.count_mismatch`, `acl.trailing_bytes` (**non-zero** bytes after `AceCount` ACEs: a parser iterating to `AclSize` would see more ACEs than one that counts, the classic differential) | `acl.non_canonical` (with the failing rule and index) |
| `ace.size_unaligned`, `ace.size_too_small`, `ace.size_overrun`, `ace.object_overrun`, `ace.object_flags_unknown` (bits other than 0x1/0x2) | `ace.unknown_flags` (undefined `AceFlags` bits) |
| `sid.bad_revision`, `sid.bad_subauth_count` (>15), `sid.overrun` | `sd.rm_bits_set`, `sd.null_dacl` (the NULL state, so a guard can look for it) |

The overlap rule is our strictness, not Microsoft's: the spec allows components in any order but does not say overlap is legal; no AD-produced SD overlaps `[UNVERIFIED]`. We "may reject more" (R3/FF-SP6 stance). If a real DC ever emits one, the corpus gets a new `hostile:false` record and the rule is narrowed; we do not repair.

---

## 5. Hostile vectors

Notation as in `safe-primitives.md`. **Baseline V01** (valid, 60 bytes; owner `S-1-5-18`, no group/SACL, DACL rev 2 with one allow ACE, mask `0x000F01FF`, trustee `S-1-5-18`):

```text
off  0: 01 00 04 80  30 00 00 00  00 00 00 00  00 00 00 00  14 00 00 00      Revision=1 Control=0x8004(SR|DP) Owner@48 Group=0 Sacl=0 Dacl@20
off 20: 02 00 1c 00  01 00 00 00                                             ACL rev2 size 0x1c count 1
off 28: 00 00 14 00  ff 01 0f 00                                             ACE type0 flags0 size 0x14 mask 0x000f01ff
off 36: 01 01 00 00 00 00 00 05 12 00 00 00                                  SID S-1-5-18 (trustee)
off 48: 01 01 00 00 00 00 00 05 12 00 00 00                                  SID S-1-5-18 (owner)
```

"Mutation" vectors give the byte changes from V01. Two corpus units (the FF-SP4 gate counts per unit, `safe-primitives.md` §8): **`sd.read`** (decoder, control encoder, helper, display) and **`sd.write`** (planner). `sd.write` is gated only when its build ticket lands (§11); until then it has no implementation to skip. Each unit needs ≥ 10 hostile records after expansion (FF-SP4); expanding the `/` rows, the tables give about 32 for `sd.read` (static records SD-S01…S09 counted in it, so more) and 17 for `sd.write`.

### 5.1 `sd.read` — decode

| ID | Input | Expected | Hostile | Why |
| --- | --- | --- | --- | --- |
| SD-01 | V01 | owner `S-1-5-18`; group absent; DACL List rev 2, 1 ACE: Basic allow, mask 0x000F01FF, trustee `S-1-5-18`; Control 0x8004; no anomalies; pins the Control bit values | no | positive anchor |
| SD-02 | V01 truncated to 40 bytes | `sd.truncated` (DACL claims bytes 20–47, owner at 48) | yes | truncated ACL/SD |
| SD-03 | first 19 bytes of V01 | `sd.truncated_header` | yes | |
| SD-04 | byte 24 = `02` (AceCount 2, AclSize unchanged) | `acl.count_mismatch`: second ACE cannot fit in `AclSize` | yes | ACE count mismatch (over) |
| SD-05 | byte 24 = `00` (AceCount 0, ACE bytes still present) | `acl.trailing_bytes` | yes | count-versus-size parser differential (under) |
| SD-06 | bytes 16–19 = `f0 ff ff ff` | `sd.offset_out_of_range` | yes | offset past end |
| SD-07 | bytes 16–19 = 0, Control still has DP | DACL state **Null**, anomaly `sd.null_dacl`; helper answers Yes for every right | no | NULL ≠ empty ≠ absent `[UNVERIFIED on AD wire]` |
| SD-08 | byte 2 = `00` (DP clear) while OffsetDacl ≠ 0 | `sd.dacl_offset_without_flag` | yes | offset/flag disagreement |
| SD-09 | byte 3 = `00` (SR clear) | `sd.not_self_relative` | yes | |
| SD-10 | byte 0 = `02` | `sd.bad_revision` | yes | |
| SD-11 | byte 30 = `13` (AceSize 19) | `ace.size_unaligned` | yes | |
| SD-12 | bytes 30–31 = `08 00` | `ace.size_too_small` (type 0 needs ≥ 16) | yes | |
| SD-13 | byte 37 = `ff` (trustee SID subauthority count 255) | `sid.bad_subauth_count` (no read past the ACE) | yes | |
| SD-14 | ACL rev 2 holding a well-formed type 0x05 object ACE | `acl.revision_type_mismatch` | yes | rev 4 only for object ACEs |
| SD-15 | object ACE, `Flags` = 3 but `AceSize` holds one GUID | `ace.object_overrun` | yes | object-ACE layout |
| SD-16 | object ACE, `Flags` = 5 | `ace.object_flags_unknown` | yes | |
| SD-17 | object ACE, `Flags` = 0 (no GUIDs) with SID right after `Flags` | decodes; trustee correct; ObjectType nil | no | variable layout positive |
| SD-18 | object ACE, `Flags` = 2 (only InheritedObjectType) | decodes; trustee correct; ObjectType nil, InheritedObjectType set | no | a fixed-offset parser reads the wrong SID here |
| SD-19 | DACL type 0x7F (valid size) | decodes; `Opaque` ACE; anomaly `ace.opaque`; edit refused; helper `Unknown` for rights it could affect | yes | unknown type neutralised |
| SD-20 | DACL containing audit type 0x02 | anomaly `ace.misplaced_type`; not editable | yes | MS-DTYP "unspecified behavior" |
| SD-21 | DACL: allow ACE then deny ACE for the same trustee/right | decodes; anomaly `acl.non_canonical` (rule 2, index 1); **helper evaluates in stored order ⇒ Yes** | yes | no silent re-sort in the read path |
| SD-22 | DACL: INHERITED ACE (flags 0x10) before an explicit ACE | anomaly `acl.non_canonical` (rule 1) | yes | |
| SD-23 | owner offset 24 (inside the DACL) | `sd.components_overlap` | yes | our strictness, §4 |
| SD-24 | `AclSize` = `ff ff`; `AceCount` = `ff ff` (two records) | `acl.size_out_of_range`; `acl.count_mismatch` **before any allocation** | yes | memory exhaustion |
| SD-25 | 1 MiB input | `sd.too_large` | yes | R5 |

### 5.2 `sd.read` — control encoder, helper, connector contract

| ID | Input | Expected | Hostile | Why |
| --- | --- | --- | --- | --- |
| SD-C01 | `ReadControl(DACL)` / `ReadControl(OWNER\|GROUP\|DACL)` | `30 03 02 01 04` / `30 03 02 01 07`, OID `1.2.840.113556.1.4.801`, critical | no | |
| SD-C02 | `ReadControl(0)` | `sd.flags_empty` | yes | the server treats 0 as 15 (all four, SACL included) |
| SD-C03 | `ReadControl(SACL)` / `(OWNER\|…\|SACL)` without `SACLCap` | `sd.sacl_requires_capability` | yes | SACL needs SeSecurityPrivilege, Tier-0 |
| SD-C04 | `ReadControl(0x14)` | `sd.flags_unknown_bits` | yes | server would ignore bit 0x10 |
| SD-C05 | search for `nTSecurityDescriptor` with an identity lacking `SeSecurityPrivilege` and `Parts` = 0x7 | the DACL is returned; no SACL expected; no error | no | T-0118 AC 3; lab |
| SD-C06 | search whose attribute list names `nTSecurityDescriptor`, `*` or is empty, built without `ReadControl` | refused by the connector: `sd.read_requires_flags` (static where possible, runtime otherwise) | yes | no control = flags 15 |
| SD-C07 | entry returned without `nTSecurityDescriptor` | `sd.not_returned`, not an empty SD | yes | absence ≠ "no ACEs" |
| SD-H01 | OU DACL: object ACE allow, mask 0x100, ObjectType `00299570-246d-11d0-a768-00aa006e0529`, InheritedObjectType user class, flags CI\|INHERIT; child user holds the inherited copy (0x10); trustee X in the principal | helper on the child: **Yes**, source = that ACE, `Inherited=true`. Bytes of the GUID: `70 95 29 00 6d 24 d0 11 a7 68 00 aa 00 6e 05 29` | no | T-0118 AC 2 anchor; GUID endianness |
| SD-H02 | same ACE on the OU object itself with INHERIT_ONLY (0x08) | helper on the OU: **No** | no | inherit-only ACEs do not apply to their own object |
| SD-H03 | allow, mask 0x100, **no** ObjectType | helper for Reset-Password: **Yes** | no | absent GUID = all extended rights |
| SD-H04 | allow, mask 0x20 (WP), ObjectType = Reset-Password right GUID | helper for Reset-Password: **No** | yes | inert ACE: right GUID with a property mask |
| SD-H05 | trustee `S-1-5-10` (SELF), no `SelfSID` | **Unknown** (guard treats as Yes) | yes | |
| SD-H06 | callback ACE type 0x09 matching the principal | **Unknown** | yes | conditions not evaluated |
| SD-H07 | empty DACL | helper: No for every right except implicit owner READ_CONTROL/WRITE_DAC (Unknown) | no | empty ≠ NULL |
| SD-H08 | principal built from the user's SID only (no `tokenGroups`) when the grant is to a group | **No**, plus `Principal.Incomplete=true` in the result (the type cannot prove completeness, so the constructor from a DC response sets it; hand-built principals carry `Incomplete`) | yes | membership comes from the DC, not guessed |

### 5.3 `sd.write` (write half)

| ID | Input | Expected | Hostile | Why |
| --- | --- | --- | --- | --- |
| SD-E01 | `Remove` of an ACE with INHERITED (0x10) | `sd.inherited_ace_immutable` | yes | inherited-ACE edit |
| SD-E02 | `Add` with INHERITED set | `sd.inherited_flag_on_new` | yes | forging the inherited block |
| SD-E03 | `Add` mask with GA (0x10000000) | `sd.generic_mask` (use specific bits) | yes | AD never stores generics |
| SD-E04 | `Add` mask with SYNCHRONIZE (0x00100000) | `sd.mask_unsupported_bits` | yes | "ignored in AD DACLs" |
| SD-E05 | `Add` object ACE, ObjectType GUID not in the catalog | `sd.unknown_object_type` | yes | |
| SD-E06 | `Add` WP with ObjectType = control-access GUID | `sd.object_type_mismatch` | yes | inert ACE |
| SD-E07 | `Add` with INHERIT_ONLY but neither OBJECT_ nor CONTAINER_INHERIT | `sd.inert_ace` | yes | an ACE that applies nowhere |
| SD-E08 | base DACL non-canonical, `Add` without `Normalize` | `sd.base_non_canonical`; with `Normalize` a plan listing the effective-rights change | yes | reorder changes access |
| SD-E09 | result would exceed 65 535 bytes or 4 095 ACEs | `sd.acl_too_large` | yes | 16-bit AclSize |
| SD-E10 | `Remove` index valid, digest of another ACE | `sd.ace_digest_mismatch` | yes | stale index removes the wrong ACE |
| SD-E10b | DACL changed on the DC between read and write (base digest differs) | `sd.stale_base`, no write | yes | lost update |
| SD-E11 | object in the SDProp-protected set | `sd.sdprop_will_revert` | yes | edit reverted within ~60 min |
| SD-E12 | `Value()` of any `DACLWrite` | `OffsetOwner=OffsetGroup=OffsetSacl=0`, `SP` clear, `DP` set, control `30 03 02 01 04` critical | yes | belt and braces for 6.1.3.2 |
| SD-E13 | diff that removes every ACE granting WRITE_DAC to the connector's own principal and the connector is not owner | `sd.self_lockout` | yes | |
| SD-E14 | diff that tries to change `PD` or `DI` | `sd.protect_flag_change` (use `PlanInheritance`) | yes | |
| SD-E15 | base with an `Opaque` ACE | `sd.not_editable` | yes | §4 |
| SD-E16 | `Add` whose trustee is built from a name or alias | does not compile / `sd.trustee_not_sid` at the one place a string enters (a test through the JSON API) | yes | SD-R2 |

### 5.4 Static vectors (`"kind":"static"`, checked by the lint rule, §6)

| ID | Code | Expected |
| --- | --- | --- |
| SD-S01 | `windows.SecurityDescriptorFromString(…)` anywhere in product code | FF-SD1 fails, naming the file |
| SD-S02 | string literal `"D:(A;;GA;;;BA)"` flowing to a modify | FF-SD2 fails |
| SD-S03 | `fmt.Sprintf("O:%sG:%sD:%s", o, g, d)` | FF-SD2 fails |
| SD-S04 | .NET `new RawSecurityDescriptor(sddl)` / `SetSecurityDescriptorSddlForm` in the sidecar | FF-SD1 fails |
| SD-S05 | `binary.LittleEndian.Uint32(raw[4:8])` on a value read from `nTSecurityDescriptor` outside `sd` | FF-SD3 fails (type `sd.Raw`, no conversion outside) |
| SD-S06 | a modify request naming `ntsecuritydescriptor` (any case) built outside `sd` | FF-SD3 fails |
| SD-S07 | a function in `sd` with signature `func(string) SD`, or a name matching `Parse*SDDL|FromSDDL|*SDDL*` that returns anything but `SDDLDisplay` | FF-SD4 fails |
| SD-S08 | `SDDLDisplay` passed to any function outside the response-mapping package | FF-SD4 fails |
| SD-S09 | TS/TSX template literal containing SDDL shape under `web/` | FF-SP3 (extended) fails |

---

## 6. SDDL is display-only, and the lint rule

**Why SDDL is banned on write paths.** [SDDL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format) (doc):
- is lossy: `DEFAULTED` bits and `SR` are not stored; `RM` bits are not carried; **a NULL ACL cannot be written** (bare `D:` means *empty*, the opposite meaning); the string omits whatever the caller's `SECURITY_INFORMATION` omitted;
- resolves domain-relative aliases (`DA`, `EA`, `DU`, `DD`, …) against the **caller's own domain** on conversion (doc, SID strings; I did not confirm the exact resolution rule for every alias `[UNVERIFIED]`), so a string built or tested in one domain names another domain's groups in a second forest;
- hides ACE order, the INHERITED flag and ACE types we do not handle behind one-letter codes;
- is parsed by platform code whose behaviour differs between Windows, Samba and .NET.

**The renderer.** `DisplaySDDL()` is the one place SDDL exists. It emits numeric SIDs for every domain-relative principal and
aliases only for the fixed well-known set (`WD`, `BA`, `SY`, `AU`, …) so that the text can be compared with `Get-Acl … .Sddl`; it never emits a
string we would accept back. It is an output of the typed model, tested against the Windows `ConvertSecurityDescriptorToStringSecurityDescriptor`
oracle in the Windows lab (FF-SP6 extension; a Samba oracle is not accepted: Samba has its own SDDL encoder).
There is no parser: **no function in the product turns SDDL text into an SD, ACE or `DACLWrite`**. Importing an admin-supplied SDDL string
is a separate feature that would need its own validated front end and an ADR; it is not smuggled in through a helper.
Tier L (lab and tools) may use SDDL to author fixtures.

**Fitness rules** (implemented in the T-0033 static check; T-0118 AC 4 adds the first planted-violation test):

| FF | Check | Fails when |
| --- | --- | --- |
| FF-SD1 | Banned APIs (forbidigo, BannedApiAnalyzers) | any of these outside `sd`: Go `golang.org/x/sys/windows` `SecurityDescriptorFromString`, `(*SECURITY_DESCRIPTOR).String`, `SetEntriesInAcl`/`ACLFromEntries`, `SetNamedSecurityInfo`/`SetSecurityInfo`/`GetNamedSecurityInfo`; Win32 `ConvertStringSecurityDescriptorTo…`, `ConvertSecurityDescriptorToString…`; .NET `RawSecurityDescriptor(string)`, `CommonSecurityDescriptor` SDDL members, `SetSecurityDescriptorSddlForm`/`GetSddlForm`, `ActiveDirectorySecurity`/`ObjectSecurity` SDDL members; PowerShell `Set-Acl`, `ConvertFrom-SddlString` (also absent from every `psx` manifest, FF-SP9). A third-party ACL library (feasibility names [winacl](https://github.com/TheManticoreProject/winacl), MIT, `[UNVERIFIED]` here) may be imported **only inside `sd`**, only after the licence register check (rule 9), and its SDDL functions stay banned inside `sd` too |
| FF-SD2 | SDDL literal-shape scanner (Semgrep or ast-grep, case-insensitive; `web/` included, tier L and `testdata/` exempt) | a string literal matching `\b[DS]:(?:P\|AI\|AR\|NO_ACCESS_CONTROL)*\((?:A\|D\|OA\|OD\|AU\|AL\|OU\|OL\|ML\|XA\|XD\|ZA\|XU\|RA\|SP\|TL)?;` or `\bO:(?:[A-Z]{2}\|S-1-)[^;]*G:`, **or** concatenation/`Sprintf` producing those prefixes, outside `sd`'s renderer. Exemptions are listed in a reviewed allow-file with a reason each |
| FF-SD3 | Raw-bytes boundary (go/analysis pass `sdraw`; `forbidigo` for names) | `sd.Raw` converted to `[]byte`, indexed or sliced outside `sd` and the connector; any modify request whose attribute equals `nTSecurityDescriptor` (case-insensitive) constructed outside `sd`; a search that selects the attribute without `ReadControl` (SD-C06) |
| FF-SD4 | API shape (go/analysis pass `sdapi`) | an exported `sd` function accepts a `string`/`[]byte` and returns `SD`, `ACE`, `ACL`, `DACLWrite` or `Raw` (only `Decode(Raw)` and the P3 SID/GUID constructors exist); a name matching `(?i)sddl` returning anything but `SDDLDisplay`; `SDDLDisplay` used outside the response-mapping package; `DACLWrite` constructed other than through `Plan*` |
| FF-SD5 | Corpus and fuzz | unit `sd.read` or `sd.write` below 10 hostile records; no corpus-seeded fuzz target for `Decode` (properties: no panic, bounded allocation, `Decode(x)` ok ⇒ every ACE's bytes lie inside the ACL; for editable SDs `Decode(Plan(...).Value())` round-trips) |

---

## 7. Version dependence the implementer must not paper over

| Topic | Behaviour | Source |
| --- | --- | --- |
| Implicit owner rights and DACL write | CVE-2021-42291 updates (Nov 2021; Windows Server 2008 SP2 to 2022) block owner-implicit WRITE_DAC for non-DA/EA on computer objects when the heuristic is on; Windows 11 22H2+ have the DACL-write requirement in the base; Windows 11 26H1 changes the heuristic default and adds ACE-by-ACE rules. A DACL write that works on one DC patch level can fail on another | doc ([6.1.3.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c), [6.1.3.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7afacb02-548b-4e74-bf96-04b0bf0c71b6)) |
| SD_FLAGS on Modify | the clarification in 3.1.1.3.4.1.11 footnote 2 applies to the OS versions with the CVE-2021-42291 updates; before them, behaviour of the control on Modify is not specified `[UNVERIFIED]`. This is why writes also zero the unwanted offsets and make the control critical | doc |
| Object ACEs | need ACL rev 4; AD DS only | doc |
| `LIST_OBJECT` | not enforced unless `dSHeuristics` fDoListObject is TRUE; the helper takes the forest's heuristic as an input | doc |
| Supported DC versions | which Windows Server versions we support is a scope decision (product-manager / ceo-decisions), not made here | — |

---

## 8. What T-0118 builds and what is deferred

T-0118 (read half): `Decode`, anomalies, `IsCanonical`, `ReadControl`, `Grants`, `DisplaySDDL`, units `sd.read` records SD-01…SD-25, SD-C01…C07, SD-H01…H08, and FF-SD1–FF-SD4 as static checks (the write API not existing yet, FF-SD4 passes trivially for it). T-0053 consumes `Grants` and the connector's control wiring. Deferred (§11): `PlanDACL`/`PlanInheritance`/`DACLWrite`, `sd.write` records, SACL read capability issuance, SD-valued attributes other than `nTSecurityDescriptor`.

## 9. Verification status and Samba false-pass risks

Nothing is lab-verified (the Samba lab, T-0012, exists but no SD test has been run on it; no Windows DC lab covers these rows yet, see T-0051). "Where" = where the behaviour must be confirmed before the corpus record may say `verified`.

| Behaviour | Status | Verify on | Samba false-pass risk |
| --- | --- | --- | --- |
| SD, ACL, ACE and object-ACE byte layouts; rev 2/4 rules | doc (MS-DTYP) | Samba + Windows | low: wire format is shared, but both lab runs only exercise what *their* DC emits |
| Canonical ordering rules (five rules) | doc | Windows | — (pure computation; test is a unit test) |
| DC evaluates in stored order | doc (MS-ADTS 5.1.3.1) | Windows | medium |
| DC accepts/rejects/reorders a non-canonical DACL on modify | `[UNVERIFIED]` | Windows **and** Samba, compared | **high**: Samba may re-sort or reject; a Samba pass is no evidence for Windows |
| SD_FLAGS encoding; flags 0 ⇒ 15; no control ⇒ 15; SD returned only if named/`*` with control | doc | Samba + Windows | **medium**: if Samba treats an absent control as 7, SD-C06 would pass falsely |
| Search with SACL bit and no `SeSecurityPrivilege`: omitted vs error | `[UNVERIFIED]` | Windows | **high**; privilege handling differs on Samba |
| DACL-only modify leaves owner/group/SACL untouched | doc (6.1.3.2) | Windows (patched and, if supported, unpatched) + Samba | medium; version dependent, see §7 |
| Write authorization: WRITE_DAC or owner-implicit; owner-set rules; SeRestorePrivilege | doc (6.1.3.5) | Windows | **high**: Samba's implicit-owner and privilege behaviour `[UNVERIFIED]` |
| Generic bits mapped on store; X bits ignored | doc (MS-ADTS access rights) | Windows + Samba | medium |
| DC recomputes inherited ACEs; client DACL without `DI` | `[UNVERIFIED]` | Windows | **high**: a Samba note says it strips `ACE_INHERITED` without `DI` (doc+blog) |
| `InheritedObjectType` kept on inherited copies | `[UNVERIFIED]` | Windows | high |
| NULL DACL representation on the AD wire | `[UNVERIFIED]` | Windows | medium |
| SDProp rewrite (≈60 min, PDC emulator) and DACL-protected on protected objects | doc+blog | **Windows only** | **high**: Samba's AdminSDHolder behaviour `[UNVERIFIED]`; any Samba test of SD-E11 is meaningless |
| `sDRightsEffective` bits (owner covers group) | doc+secondary | Samba + Windows | medium: Samba support `[UNVERIFIED]` |
| Inheritance fan-out events/uSN | `[UNVERIFIED]` | Windows | medium |
| Atomic compare via delete-old/add-new on the SD | `[UNVERIFIED]` | Windows | high |
| SDDL renderer equals `ConvertSecurityDescriptorToStringSecurityDescriptor` | doc | **Windows** | **high**: Samba's encoder differs; oracle must be Windows |
| Rights catalog GUIDs (class, attribute, property set, control access) from the schema | doc | Windows (full schema) | **high**: Samba's schema and `controlAccessRight` set differ (vacuous pass if a GUID is missing, as with LF-38 in `safe-primitives.md` §9) |

## 10. Open items for the lab and for decisions

1. Lab runs (test-engineer, T-0136): the rows marked `[UNVERIFIED]` above, each recorded as a `verified` update to the corpus record.
2. Whether to adopt winacl or write `sd` ourselves: decided by directory-engineer in T-0118 against §6 FF-SD1 (licence register first).
3. Importing admin-supplied SDDL (a "paste an SDDL" feature) is not specified and not planned.

## 11. Follow-ups

- Build ticket for the write half (`PlanDACL`, `PlanInheritance`, `DACLWrite`, `sd.write` records, SD-E01…E16), depends on T-0118 and the lab verification of the write-path rows in §9 (T-0135).
- Lab verification ticket for the `[UNVERIFIED]` rows in §9 (T-0136).
- Spec for SD-valued attributes other than `nTSecurityDescriptor` (RBCD, gMSA membership) when T-0053 or a delegation report needs to write them.
- `safe-primitives.md` §8 gains the units `sd.read` and `sd.write` and the FF-SD rows by reference (done in this change).
