#!/usr/bin/env python3
"""Generates testdata/safe-primitives/sd.write.jsonl (records SD-E01..E17 and SD-W*).

Run from the repository root:  python3 -I internal/directory/sd/testdata/gen_write_corpus.py

Independent oracle (Tier L): the bytes of every expected write are laid out here by hand from
MS-DTYP 2.4.x and from the canonical-position rule of safe-primitives-security-descriptor SD-R8,
not by calling or mirroring the Go planner. The helpers are copied from gen_corpus.py because
`python3 -I` does not put the script directory on sys.path.
"""
import hashlib, json, struct, uuid

def sid(text):
    p = text.split("-")
    return bytes([1, len(p) - 3]) + int(p[2], 0).to_bytes(6, "big") + b"".join(struct.pack("<I", int(x)) for x in p[3:])

def guid(text): return uuid.UUID(text).bytes_le

def ace(t, flags, mask, trustee, obj=None, inh=None, size=None, objflags=None):
    body = struct.pack("<I", mask)
    if t in (5, 6):
        body += struct.pack("<I", (1 if obj else 0) | (2 if inh else 0))
        if obj: body += guid(obj)
        if inh: body += guid(inh)
    body += sid(trustee)
    return bytes([t, flags]) + struct.pack("<H", 4 + len(body) if size is None else size) + body

def acl(aces, rev=2):
    body = b"".join(aces)
    return bytes([rev, 0]) + struct.pack("<HHH", 8 + len(body), len(aces), 0) + body

def sd(dacl=None, owner=None, group=None, control=0x8000, null_dacl=False):
    parts, offs, off = [], {}, 20
    for name, v in (("dacl", dacl), ("owner", owner), ("group", group)):
        if v is None: offs[name] = 0; continue
        offs[name] = off; parts.append(v); off += len(v)
    if dacl is not None or null_dacl: control |= 4
    return bytes([1, 0]) + struct.pack("<H", control) + struct.pack("<IIII", offs["owner"], offs["group"], 0, offs["dacl"]) + b"".join(parts)

def written(aces, rev, control=0x8004):
    """What Value() must be: header with owner/group/SACL offsets 0, DACL right after it."""
    return bytes([1, 0]) + struct.pack("<H", control) + struct.pack("<IIII", 0, 0, 0, 20) + acl(aces, rev)

def dacl_digest(aces, rev, control=0):
    h = hashlib.sha256()
    h.update(bytes([2, rev]) + struct.pack("<H", control & 0x1400) + struct.pack("<I", len(aces)))
    for a in aces: h.update(struct.pack("<I", len(a)) + a)
    return h.hexdigest()

SYS, EVERYONE, AU = "S-1-5-18", "S-1-1-0", "S-1-5-11"
DOM = "S-1-5-21-1004336348-1177238915-682003330"
X1, G1 = DOM + "-1105", DOM + "-1200"
GUESTS, ADMINS, RAS = "S-1-5-32-546", "S-1-5-32-544", "S-1-5-32-560"
ATTR1 = "bf9679c0-0de6-11d0-a285-00aa003049e2"      # member (attribute)
PSET = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"       # Membership (property set)
CTRL = "00299570-246d-11d0-a768-00aa006e0529"       # Reset Password (control access)
VWRITE = "bf9679a8-0de6-11d0-a285-00aa003049e2"     # stand-in validated write
CLASS = "bf967aba-0de6-11d0-a285-00aa003049e2"      # user (class)
UNKNOWN = "11111111-2222-3333-4444-555555555555"
CATALOG = {ATTR1: "attribute", PSET: "property_set", CTRL: "control_access", VWRITE: "validated_write", CLASS: "class"}
CONN = {"user": X1, "groups": [G1, AU, EVERYONE]}

recs = []
def rec(id_, call, args, expect, hostile, source):
    recs.append({"id": id_, "primitive": "sd.write", "call": call, "args": args, "expect": expect,
                 "hostile": hostile, "source": "safe-primitives-security-descriptor §5.3 " + source, "verified": "doc"})

def hx(b): return {"hex": b.hex()}
def js(v): return {"utf8": json.dumps(v, separators=(",", ":"), sort_keys=True)}
def dg(a): return hashlib.sha256(a).hexdigest()

def plan(id_, base, add=(), remove=(), opts=None, expect=None, hostile=True, source="", catalog=CATALOG):
    o = {"connector": CONN}
    o.update(opts or {})
    args = {"sd": hx(base), "add": js(list(add)), "remove": js(list(remove)), "opts": js(o), "catalog": js(catalog)}
    rec(id_, "PlanDACL", args, {"error": expect} if isinstance(expect, str) else {"value": expect}, hostile, source)

def outcome(sdbytes, inserted=(), removed=(), moves=(), changes=(), incomplete=False, noncanon=(), control=0x8004):
    return {"sd_hex": sdbytes.hex(), "control_hex": "3003020104", "critical": True, "offsets": [0, 0, 0, 20],
            "control": control, "inserted": list(inserted), "removed": list(removed), "moves": [list(m) for m in moves],
            "changes": list(changes), "changes_incomplete": incomplete, "noncanonical": [list(n) for n in noncanon]}

def new(trustee, mask, deny=False, obj=None, inh=None, flags=0):
    d = {"trustee": trustee, "mask": mask, "deny": deny, "flags": flags}
    if obj: d["object"] = obj
    if inh: d["inherited_object"] = inh
    return d

# --- base objects -----------------------------------------------------------------------------
B = [ace(1, 0, 0x20, GUESTS),                       # 0 deny Guests WP
     ace(0, 0, 0xF01FF, SYS),                       # 1 allow SYSTEM full
     ace(0, 0, 0x60000, G1),                        # 2 allow G1 READ_CONTROL|WRITE_DAC (the connector's route to WRITE_DAC)
     ace(5, 0, 0x10, AU, obj=ATTR1),                # 3 allow AU read member (scoped)
     ace(0, 0x10, 0x20, ADMINS)]                    # 4 allow Administrators WP, INHERITED
BASE = sd(dacl=acl(B, 4), owner=sid(SYS), control=0x8000)
BASE_OWNER_CONN = sd(dacl=acl(B, 4), owner=sid(X1))

# SD-E01
plan("SD-E01", BASE, remove=[{"index": 4, "digest": dg(B[4])}], expect="sd.inherited_ace_immutable", source="SD-E01")
plan("SD-E02", BASE, add=[new(X1, 0x20, flags=0x10)], expect="sd.inherited_flag_on_new", source="SD-E02")
plan("SD-E03", BASE, add=[new(X1, 0x10000000)], expect="sd.generic_mask", source="SD-E03 GA")
plan("SD-E03B", BASE, add=[new(X1, 0x80000000)], expect="sd.generic_mask", source="SD-E03 GR")
plan("SD-E04", BASE, add=[new(X1, 0x00100000)], expect="sd.mask_unsupported_bits", source="SD-E04 SYNCHRONIZE")
plan("SD-E04B", BASE, add=[new(X1, 0x01000000)], expect="sd.mask_unsupported_bits", source="SD-E04 ACCESS_SYSTEM_SECURITY is a privilege, not a DACL bit")
plan("SD-E05", BASE, add=[new(X1, 0x20, obj=UNKNOWN)], expect="sd.unknown_object_type", source="SD-E05")
plan("SD-E05B", BASE, add=[new(X1, 0x20, obj=ATTR1, inh=UNKNOWN)], expect="sd.unknown_object_type", source="SD-E05 InheritedObjectType not in the catalog")
plan("SD-E06", BASE, add=[new(X1, 0x20, obj=CTRL)], expect="sd.object_type_mismatch", source="SD-E06 WP with a control-access GUID is inert")
plan("SD-E06B", BASE, add=[new(X1, 0x100, obj=ATTR1)], expect="sd.object_type_mismatch", source="SD-E06 CA with an attribute GUID is inert")
plan("SD-E07", BASE, add=[new(X1, 0x20, flags=0x08)], expect="sd.inert_ace", source="SD-E07 INHERIT_ONLY applies nowhere")

# SD-E08: outcome-changing order violation in the base (explicit allow before explicit deny)
N = [ace(0, 0, 0x20, G1), ace(1, 0, 0x20, G1), ace(0, 0, 0x40000, G1), ace(0, 0, 0xF01FF, SYS)]
NBASE = sd(dacl=acl(N, 2), owner=sid(SYS))
RC = new(AU, 0x20000)
plan("SD-E08", NBASE, add=[RC], expect="sd.base_non_canonical", source="SD-E08 without Normalize")
plan("SD-E08B", NBASE, add=[RC], opts={"normalize": True}, hostile=True, source="SD-E08 with Normalize: deny moves first, the reorder is reported",
     expect=outcome(written([N[1], N[0], N[2], N[3], ace(0, 0, 0x20000, AU)], 2), inserted=[4], moves=[(1, 0), (0, 1)],
                    changes=[{"trustee": G1, "mask": 0x20, "before": "yes", "after": "no"}]))

# SD-E17: SD-26 (Microsoft's User default; cosmetic violations only) is editable without Normalize
AUX = DOM + "-512"
def user_default():
    a = []
    for m, t in ((0xF01FF, DOM + "-512"), (0xF01FF, "S-1-5-18"), (0x20094, "S-1-5-32-548"), (0x20094, "S-1-5-10")):
        a.append(ace(0, 0, m, t))
    for m, g, t in ((0x100, "ab721a53-1e2f-11d0-9819-00aa0040529b", "S-1-5-10"), (0x100, "00299570-246d-11d0-a768-00aa006e0529", "S-1-5-10"),
                    (0x100, "a05b8cc2-17bc-4802-a710-e7c15ab866a2", "S-1-5-10"), (0x30, "77b5b886-944a-11d1-aebd-0000f80367c1", "S-1-5-10"),
                    (0x30, "e45795b2-9455-11d1-aebd-0000f80367c1", "S-1-5-10"), (0x30, "e45795b3-9455-11d1-aebd-0000f80367c1", "S-1-5-10"),
                    (0x10, "4c164200-20c0-11d0-a768-00aa006e0529", DOM + "-553"), (0x10, "5f202010-79a5-11d0-9020-00c04fc2d4cf", DOM + "-553"),
                    (0x10, "bc0ac240-79a9-11d0-9020-00c04fc2d4cf", DOM + "-553")):
        a.append(ace(5, 0, m, t, obj=g))
    a.append(ace(0, 0, 0x20000, AU))
    for g in ("59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "037088f8-0ae1-11d2-b422-00a0c968f939", "bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "a1990816-4298-11d1-ade2-00c04fd8d5cd"):
        a.append(ace(5, 0, 0x10, AU, obj=g))
    a.append(ace(5, 0, 0x100, "S-1-1-0", obj="ab721a53-1e2f-11d0-9819-00aa0040529b"))
    a.append(ace(5, 0, 0x10, DOM + "-553", obj="5f202010-79a5-11d0-9020-00c04fc2d4cf"))
    a.append(ace(5, 0, 0x30, DOM + "-517", obj="bf967a7f-0de6-11d0-a285-00aa003049e2"))
    return a
UD = user_default()
UDSD = sd(dacl=acl(UD, 4), owner=sid(AUX), group=sid(DOM + "-513"))
DA_CONN = {"user": X1, "groups": [AUX, AU, EVERYONE]}
n_allow, n_deny = new(RAS, 0x10, obj=ATTR1), new(GUESTS, 0x20, deny=True)
plan("SD-E17A", UDSD, add=[n_allow], opts={"connector": DA_CONN}, hostile=False, source="SD-E17 allow lands after the last explicit allow; no existing ACE moves",
     expect=outcome(written(UD + [ace(5, 0, 0x10, RAS, obj=ATTR1)], 4), inserted=[len(UD)]))
plan("SD-E17B", UDSD, add=[n_deny], opts={"connector": DA_CONN}, hostile=False, source="SD-E17 deny lands before every allow (none explicit); no existing ACE moves",
     expect=outcome(written([ace(1, 0, 0x20, GUESTS)] + UD, 4), inserted=[0]))
plan("SD-E17C", UDSD, add=[new(RAS, 0x10)], opts={"connector": DA_CONN}, hostile=False,
     source="SD-E17 (SD-R8) a whole-object allow goes before the first object-scoped allow, and the base is not reordered",
     expect=outcome(written(UD[:4] + [ace(0, 0, 0x10, RAS)] + UD[4:], 4), inserted=[4]))

# SD-E09: ACL at the 16-bit limit. 3276 ACEs of 20 bytes = 65 528 bytes; one more is 65 548.
FULL = [ace(0, 0, 0x10, EVERYONE) for _ in range(3276)]
FULLSD = sd(dacl=acl(FULL, 2), owner=sid(X1))
plan("SD-E09", FULLSD, add=[new(AU, 0x10)], expect="sd.acl_too_large", source="SD-E09 AclSize would exceed 65 535")
plan("SD-E09B", FULLSD, add=[new(AU, 0x10)], remove=[{"index": 0, "digest": dg(FULL[0])}], hostile=False,
     source="SD-E09 one out, one in: stays within the limit",
     expect=outcome(written(FULL[1:] + [ace(0, 0, 0x10, AU)], 2), inserted=[3275], removed=[0]))

# SD-E10 / E10b
plan("SD-E10", BASE, remove=[{"index": 2, "digest": dg(B[3])}], expect="sd.ace_digest_mismatch", source="SD-E10 index 2, digest of ACE 3")
plan("SD-E10C", BASE, remove=[{"index": 9, "digest": dg(B[3])}], expect="sd.ace_index_out_of_range", source="SD-E10 index past the end")
plan("SD-E10D", BASE, remove=[{"index": 3, "digest": dg(B[3])}, {"index": 3, "digest": dg(B[3])}], expect="sd.duplicate_remove", source="SD-E10 the same ACE twice")
plan("SD-E10E", BASE, add=[RC], opts={"expect_base": "00" * 32}, expect="sd.stale_base", source="SD-E10b the caller's digest is not the base's")
plan("SD-E10F", BASE, add=[RC], opts={"expect_base": dacl_digest(B, 4)}, hostile=False, source="SD-E10b the caller's digest is the base's",
     expect=outcome(written(B[:3] + [ace(0, 0, 0x20000, AU)] + B[3:], 4), inserted=[3]))
CHANGED = sd(dacl=acl(B + [ace(0, 0, 1, X1)], 4), owner=sid(SYS))
rec("SD-E10B", "VerifyBase", {"sd": hx(BASE), "add": js([RC]), "current": hx(CHANGED), "opts": js({"connector": CONN}), "catalog": js(CATALOG)},
    {"error": "sd.stale_base"}, True, "SD-E10b DACL changed on the DC between read and write: no write")
rec("SD-E10G", "VerifyBase", {"sd": hx(BASE), "add": js([RC]), "current": hx(BASE), "opts": js({"connector": CONN}), "catalog": js(CATALOG)},
    {"value": {"ok": True}}, False, "SD-E10b DACL unchanged: the write may go")

PD_ONLY = sd(dacl=acl(B, 4), owner=sid(SYS), control=0x8000 | 0x1000)
rec("SD-E10H", "VerifyBase", {"sd": hx(BASE), "add": js([RC]), "current": hx(PD_ONLY), "opts": js({"connector": CONN}), "catalog": js(CATALOG)},
    {"error": "sd.stale_base"}, True, "SD-E10b only the protected flag changed on the DC: the plan would silently clear it")

plan("SD-E11", BASE, add=[RC], opts={"sdprop": True}, expect="sd.sdprop_will_revert", source="SD-E11 object in the SDProp-protected set")

# SD-E12: Value() shape for a plain edit
plan("SD-E12", BASE, add=[new(X1, 0x20, obj=ATTR1)], hostile=True, source="SD-E12 offsets 0, SP clear, DP set, control 30 03 02 01 04 critical",
     expect=outcome(written(B[:4] + [ace(5, 0, 0x20, X1, obj=ATTR1)] + B[4:], 4), inserted=[4]))
PBASE = sd(dacl=acl(B, 4), owner=sid(SYS), group=sid(DOM + "-513"), control=0x8000 | 0x1000 | 0x0400)
plan("SD-E12B", PBASE, add=[RC], hostile=True, source="SD-E12 owner and group of the base never reach the value; PD and DI are copied from the base",
     expect=outcome(written(B[:3] + [ace(0, 0, 0x20000, AU)] + B[3:], 4, 0x8004 | 0x1000 | 0x0400), inserted=[3], control=0x8004 | 0x1000 | 0x0400))
plan("SD-E12C", sd(dacl=acl([ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x60000, G1)], 2), owner=sid(SYS)), add=[new(X1, 0x10, obj=ATTR1)], hostile=True,
     source="SD-E12 adding an object ACE to a revision-2 ACL raises the ACL to revision 4",
     expect=outcome(written([ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x60000, G1), ace(5, 0, 0x10, X1, obj=ATTR1)], 4), inserted=[2]))

# SD-E13: lockout
plan("SD-E13", BASE, remove=[{"index": 2, "digest": dg(B[2])}], expect="sd.self_lockout", source="SD-E13 removes the connector's only WRITE_DAC route")
plan("SD-E13B", BASE, add=[new(G1, 0x40000, deny=True)], expect="sd.self_lockout", source="SD-E13 an added deny takes WRITE_DAC away")
plan("SD-E13C", BASE_OWNER_CONN, remove=[{"index": 2, "digest": dg(B[2])}], hostile=False, source="SD-E13 the connector is the owner: implicit WRITE_DAC, not a lockout",
     expect=outcome(written(B[:2] + B[3:], 4), removed=[2]))

# SD-E13: the connector holds WRITE_DAC only as the owner (implicit); naming the owner or OWNER RIGHTS removes that
OWN_ONLY = sd(dacl=acl([ace(0, 0, 0xF01FF, SYS)], 4), owner=sid(X1))
plan("SD-W19", OWN_ONLY, add=[new(X1, 0x10)], expect="sd.self_lockout", source="SD-E13 any ACE for the owner drops its implicit rights")
plan("SD-W20", OWN_ONLY, add=[new("S-1-3-4", 0x10)], expect="sd.self_lockout", source="SD-E13 an OWNER RIGHTS ACE drops the owner's implicit rights")
plan("SD-W21", OWN_ONLY, add=[new(X1, 0x40000)], hostile=False, source="SD-E13 the owner ACE grants WRITE_DAC explicitly: still a route",
     expect=outcome(written([ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x40000, X1)], 4), inserted=[1]))
# SD-E13: the base already names the owner (the usual creator ACE), so the Grants reason is owner_ace_present
OWN_ACE = sd(dacl=acl([ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x10, X1)], 4), owner=sid(X1))
plan("SD-W23", OWN_ACE, add=[new("S-1-3-4", 0x20000)], expect="sd.self_lockout", source="SD-E13 OWNER RIGHTS added when the base already has an owner ACE: implicit WRITE_DAC is dropped")
OWN_ROUTE = sd(dacl=acl([ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x10, X1), ace(0, 0, 0x40000, G1)], 4), owner=sid(X1))
plan("SD-W24", OWN_ROUTE, add=[new("S-1-3-4", 0x20000)], hostile=False, source="SD-E13 the connector also holds an explicit WRITE_DAC route through a group",
     expect=outcome(written([ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x10, X1), ace(0, 0, 0x40000, G1), ace(0, 0, 0x20000, "S-1-3-4")], 4), inserted=[3]))
GRP_OWN = sd(dacl=acl([ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x10, G1)], 4), owner=sid(G1))
plan("SD-W25", GRP_OWN, add=[new("S-1-3-4", 0x20000)], expect="sd.self_lockout", source="SD-E13 the connector reaches the owner through a group SID in its token")
plan("SD-W22", OWN_ONLY, add=[RC], opts={"no_object": True}, expect="sd.object_required", source="a write bound to no object")

# SD-E14
plan("SD-E14", BASE, add=[RC], opts={"want_control": 0x8004 | 0x1000}, expect="sd.protect_flag_change", source="SD-E14 PD")
plan("SD-E14B", BASE, add=[RC], opts={"want_control": 0x8004 | 0x0400}, expect="sd.protect_flag_change", source="SD-E14 DI")
plan("SD-E14C", PBASE, add=[RC], opts={"want_control": 0x8004}, expect="sd.protect_flag_change", source="SD-E14 clearing PD by diff")

# SD-E15
OPAQUE = bytes([0x7F, 0]) + struct.pack("<H", 16) + b"\0" * 12
plan("SD-E15", sd(dacl=acl([ace(0, 0, 0xF01FF, SYS), OPAQUE], 2), owner=sid(SYS)), add=[RC], expect="sd.not_editable", source="SD-E15 Opaque ACE")
plan("SD-W01", sd(owner=sid(SYS), null_dacl=True), add=[RC], expect="sd.not_editable", source="NULL DACL: adding an ACE would turn full access into a restriction")
plan("SD-W02", sd(owner=sid(SYS)), add=[RC], expect="sd.not_editable", source="DACL absent from the base: nothing to edit")
plan("SD-W03", BASE, expect="sd.empty_diff", source="an empty diff writes nothing")
plan("SD-W04", BASE, add=[RC], opts={"connector": {"user": X1, "groups": []}, "no_connector": True}, expect="sd.connector_required", source="the lockout check needs the connector's token")
plan("SD-W05", BASE, add=[new(X1, 0x20, obj=ATTR1, flags=0x80)], expect="sd.unsupported_flags", source="audit-only AceFlags on a DACL ACE")
plan("SD-W06", BASE, add=[new(X1, 0)], expect="sd.mask_empty", source="a zero mask grants nothing")
plan("SD-W07", BASE, add=[new(X1, 0x20, obj=ATTR1, inh=ATTR1)], expect="sd.object_type_mismatch", source="InheritedObjectType must name a class")

# SD-E16 and the one place a string enters
for id_, text, why in (("SD-E16", "DA", "SDDL alias"), ("SD-E16B", "Domain Admins", "a name"), ("SD-E16C", "", "empty"),
                       ("SD-E16D", "S-1-5-32-544 ", "trailing space"), ("SD-E16E", "(A;;GA;;;DA)", "an ACE string")):
    rec(id_, "ParseTrustee", {"text": {"utf8": text}}, {"error": "sd.trustee_not_sid"}, True, "SD-E16 " + why)
rec("SD-E16F", "ParseTrustee", {"text": {"utf8": "S-1-5-32-544"}}, {"value": "S-1-5-32-544"}, False, "SD-E16 a SID string is the only accepted form")

# PlanInheritance
IB = [ace(0, 0, 0xF01FF, SYS), ace(0, 0, 0x60000, G1), ace(0, 0x10, 0x20, ADMINS), ace(1, 0x10, 0x20, GUESTS)]
IBASE = sd(dacl=acl(IB, 2), owner=sid(SYS), control=0x8000 | 0x0400)
def inh(id_, base, op, expect, hostile, source, opts=None):
    o = {"connector": CONN}; o.update(opts or {})
    rec(id_, "PlanInheritance", {"sd": hx(base), "op": {"utf8": op}, "opts": js(o)}, {"error": expect} if isinstance(expect, str) else {"value": expect}, hostile, source)
unflag = lambda a: a[:1] + bytes([a[1] & ~0x10]) + a[2:]
inh("SD-W10", IBASE, "block_keep", outcome(written([IB[0], IB[1], unflag(IB[2]), unflag(IB[3])], 2, 0x8004 | 0x1000 | 0x0400), control=0x8004 | 0x1000 | 0x0400, noncanon=[(2, 3)]), False,
    "SD-R7 break inheritance and keep copies: INHERITED cleared, order kept (the inherited deny now sits after an allow: reported), DI copied from the base")
inh("SD-W11", IBASE, "block_remove", outcome(written(IB[:2], 2, 0x8004 | 0x1000 | 0x0400), removed=[2, 3], control=0x8004 | 0x1000 | 0x0400), False,
    "SD-R7 break inheritance and remove the inherited ACEs")
PIB = sd(dacl=acl(IB, 2), owner=sid(SYS), control=0x8000 | 0x1000 | 0x0400)
inh("SD-W12", PIB, "restore", outcome(written(IB, 2, 0x8004 | 0x0400), control=0x8004 | 0x0400), False, "SD-R7 restore inheritance clears PD only")
inh("SD-W13", PIB, "block_keep", "sd.inheritance_unchanged", True, "already protected")
inh("SD-W14", IBASE, "restore", "sd.inheritance_unchanged", True, "not protected: nothing to restore")
inh("SD-W15", IBASE, "bogus", "sd.bad_inheritance_op", True, "unknown operation")
inh("SD-W16", IBASE, "block_keep", "sd.sdprop_will_revert", True, "SD-E11 applies to PlanInheritance too", opts={"sdprop": True})
LB = [ace(0, 0, 0xF01FF, SYS), ace(0, 0x10, 0x60000, G1)]
inh("SD-W17", sd(dacl=acl(LB, 2), owner=sid(SYS), control=0x8000 | 0x0400), "block_remove", "sd.self_lockout", True, "SD-E13 the connector's WRITE_DAC route was inherited and is dropped")
inh("SD-W18", sd(dacl=acl([ace(1, 0, 0x20, GUESTS), ace(0, 0, 0x60000, G1), ace(0, 0x10, 0x20, ADMINS), ace(1, 0x10, 0x20, ADMINS)], 2), owner=sid(SYS)), "block_keep",
    outcome(written([ace(1, 0, 0x20, GUESTS), ace(0, 0, 0x60000, G1), ace(0, 0, 0x20, ADMINS), ace(1, 0, 0x20, ADMINS)], 2, 0x8004 | 0x1000), control=0x8004 | 0x1000,
            noncanon=[(2, 3)]), False,
    "converting inherited ACEs to explicit ones keeps their order (rights unchanged) and reports the rule-2 violation it leaves")

with open("testdata/safe-primitives/sd.write.jsonl", "w") as f:
    for r in recs:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")
print(len(recs), "records,", sum(1 for r in recs if r["hostile"]), "hostile")
