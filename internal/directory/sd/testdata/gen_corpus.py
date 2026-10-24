#!/usr/bin/env python3
"""Generates testdata/safe-primitives/sd.read.jsonl.

Run from the repository root:  python3 -I internal/directory/sd/testdata/gen_corpus.py

The bytes are built here, independently of the Go decoder, from MS-DTYP 2.4.x: this script is the
oracle the Go code is checked against. Tier L (lab and tools): it may use any construction it likes,
product code may not.
"""
import json, struct, uuid

def sid(text):
    p = text.split("-")
    auth = int(p[2], 0)
    subs = [int(x) for x in p[3:]]
    return bytes([1, len(subs)]) + auth.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)

def guid(text):
    return uuid.UUID(text).bytes_le

SUMMARY = {}

def ace(t, flags=0, mask=0, trustee="S-1-5-18", obj=None, inh=None, pad=0, size=None, objflags=None, tail=b""):
    body = struct.pack("<I", mask)
    if t in (5, 6, 7, 0x0B, 0x0C, 0x0F):
        of = (1 if obj else 0) | (2 if inh else 0) if objflags is None else objflags
        body += struct.pack("<I", of)
        if obj: body += guid(obj)
        if inh: body += guid(inh)
    body += sid(trustee) + tail + b"\0" * pad
    n = 4 + len(body) if size is None else size
    out = bytes([t, flags]) + struct.pack("<H", n) + body
    d = {"type": t, "flags": flags, "mask": mask, "trustee": trustee}
    if obj: d["objectType"] = obj
    if inh: d["inheritedObjectType"] = inh
    SUMMARY[out] = d
    return out

def acl(aces, rev=2, count=None, size=None, slack=b"", sbz1=0, sbz2=0):
    body = b"".join(aces) + slack
    return bytes([rev, sbz1]) + struct.pack("<HHH", 8 + len(body) if size is None else size,
        len(aces) if count is None else count, sbz2) + body

def sd(dacl=None, sacl=None, owner=None, group=None, control=0x8000, null_dacl=False, rm=0):
    parts, off = [], 20
    offs = {}
    for name, v in (("dacl", dacl), ("sacl", sacl), ("owner", owner), ("group", group)):
        if v is None: offs[name] = 0; continue
        offs[name] = off; parts.append(v); off += len(v)
    if dacl is not None or null_dacl: control |= 0x0004
    if sacl is not None: control |= 0x0010
    head = bytes([1, rm]) + struct.pack("<H", control) + struct.pack("<IIII", offs["owner"], offs["group"], offs["sacl"], offs["dacl"])
    return head + b"".join(parts)

SYS = "S-1-5-18"
V01 = sd(dacl=acl([ace(0, 0, 0x000F01FF, SYS)]), owner=sid(SYS))
SPEC_V01 = ("01000480300000000000000000000000" "14000000" "02001c0001000000" "00001400ff010f00"
            "010100000000000512000000" "010100000000000512000000")
assert V01.hex() == SPEC_V01, V01.hex()

def mut(b, off, data):
    b = bytearray(b); b[off:off + len(data)] = data; return bytes(b)

recs = []
def rec(id_, call, args, expect, hostile, source, verified="doc"):
    recs.append({"id": id_, "primitive": "sd.read", "call": call, "args": args, "expect": expect,
                 "hostile": hostile, "source": source, "verified": verified})

def hexarg(b): return {"hex": b.hex()}
def dec(id_, b, expect, hostile, source):
    if isinstance(expect, str):
        rec(id_, "Decode", {"sd": hexarg(b)}, {"error": expect}, hostile, source)
    else:
        rec(id_, "Decode", {"sd": hexarg(b)}, {"value": expect}, hostile, source)

S = "safe-primitives-security-descriptor §5.1 "
def ace_sum(type_, flags, mask, trustee, **kw):
    d = {"type": type_, "flags": flags, "mask": mask, "trustee": trustee}
    d.update(kw); return d

dec("SD-01", V01, {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(0, 0, 0x000F01FF, SYS)]}, "anomalies": [], "notes": []}, False, S + "SD-01 baseline V01 (pins Control bit values)")
dec("SD-02", V01[:40], "sd.truncated", True, S + "SD-02")
dec("SD-03", V01[:19], "sd.truncated_header", True, S + "SD-03")
dec("SD-04", mut(V01, 24, b"\x02"), "acl.count_mismatch", True, S + "SD-04 count over")
dec("SD-05", mut(V01, 24, b"\x00"), "acl.trailing_bytes", True, S + "SD-05 count under: parser differential")
dec("SD-06", mut(V01, 16, b"\xf0\xff\xff\xff"), "sd.offset_out_of_range", True, S + "SD-06")
dec("SD-07", mut(V01, 16, b"\0\0\0\0"), {"control": 0x8004, "owner": SYS, "dacl": {"kind": "null"}, "anomalies": ["sd.null_dacl"], "notes": []}, False, S + "SD-07 NULL DACL is neither empty nor absent [UNVERIFIED on the AD wire]")
dec("SD-08", mut(V01, 2, b"\x00"), "sd.dacl_offset_without_flag", True, S + "SD-08")
dec("SD-09", mut(V01, 3, b"\x00"), "sd.not_self_relative", True, S + "SD-09")
dec("SD-10", mut(V01, 0, b"\x02"), "sd.bad_revision", True, S + "SD-10")
dec("SD-11", mut(V01, 30, b"\x13"), "ace.size_unaligned", True, S + "SD-11")
dec("SD-12", mut(V01, 30, b"\x08\x00"), "ace.size_too_small", True, S + "SD-12")
dec("SD-13", mut(V01, 37, b"\xff"), "sid.bad_subauth_count", True, S + "SD-13")

obj_ok = lambda **kw: sd(dacl=acl([ace(5, 0, 0x100, "S-1-5-32-544", **kw)], rev=4), owner=sid(SYS))
RP = "00299570-246d-11d0-a768-00aa006e0529"
USER = "bf967aba-0de6-11d0-a285-00aa003049e2"
dec("SD-14", sd(dacl=acl([ace(5, 0, 0x100, SYS, obj=RP)], rev=2), owner=sid(SYS)), "acl.revision_type_mismatch", True, S + "SD-14 object ACE needs ACL rev 4")
dec("SD-15", sd(dacl=acl([ace(5, 0, 0x100, SYS, obj=RP, objflags=3)], rev=4), owner=sid(SYS)), "ace.object_overrun", True, S + "SD-15 flags 3 but one GUID present")
dec("SD-16", sd(dacl=acl([ace(5, 0, 0x100, SYS, obj=RP, objflags=5)], rev=4), owner=sid(SYS)), "ace.object_flags_unknown", True, S + "SD-16")
dec("SD-17", obj_ok(), {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 4, "aces": [ace_sum(5, 0, 0x100, "S-1-5-32-544")]}, "anomalies": [], "notes": []}, False, S + "SD-17 no GUIDs: SID right after Flags")
dec("SD-18", obj_ok(inh=USER), {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 4, "aces": [ace_sum(5, 0, 0x100, "S-1-5-32-544", inheritedObjectType=USER)]}, "anomalies": [], "notes": []}, False, S + "SD-18 only InheritedObjectType: fixed-offset parsers misread the SID")
dec("SD-18B", obj_ok(obj=RP, inh=USER), {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 4, "aces": [ace_sum(5, 0, 0x100, "S-1-5-32-544", objectType=RP, inheritedObjectType=USER)]}, "anomalies": [], "notes": []}, False, S + "SD-18 both GUIDs, mixed-endian")
dec("SD-19", sd(dacl=acl([bytes([0x7F, 0]) + struct.pack("<H", 16) + b"\0" * 12]), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [{"type": 0x7F, "flags": 0, "opaque": True}]}, "anomalies": ["ace.opaque@0"], "notes": []}, True, S + "SD-19 unknown type kept byte-for-byte")
dec("SD-20", sd(dacl=acl([ace(2, 0x40, 1, SYS)]), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(2, 0x40, 1, SYS)]}, "anomalies": ["ace.misplaced_type@0"], "notes": []}, True, S + "SD-20 audit ACE in a DACL: MS-DTYP unspecified behaviour")
A = ace(0, 0, 0x20, "S-1-5-32-545"); D = ace(1, 0, 0x20, "S-1-5-32-545")
dec("SD-21", sd(dacl=acl([A, D]), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(0, 0, 0x20, "S-1-5-32-545"), ace_sum(1, 0, 0x20, "S-1-5-32-545")]}, "anomalies": ["acl.order_outcome@1/r2"], "notes": []}, True, S + "SD-21 allow before deny, no silent re-sort")
I = ace(0, 0x10, 0x20, "S-1-5-32-545")
dec("SD-22", sd(dacl=acl([I, A]), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(0, 0x10, 0x20, "S-1-5-32-545"), ace_sum(0, 0, 0x20, "S-1-5-32-545")]}, "anomalies": ["acl.order_outcome@1/r1"], "notes": []}, True, S + "SD-22 inherited before explicit")
dec("SD-23", mut(V01, 4, struct.pack("<I", 24)), "sd.components_overlap", True, S + "SD-23 owner inside the DACL")
dec("SD-24A", mut(V01, 22, b"\xff\xff"), "sd.truncated", True, S + "SD-24 AclSize ffff (amended: claims bytes past the buffer; no allocation is sized from it)")
dec("SD-24B", mut(V01, 24, b"\xff\xff"), "acl.count_mismatch", True, S + "SD-24 AceCount ffff, refused before any allocation")
dec("SD-24C", mut(V01, 22, b"\x07\x00"), "acl.size_out_of_range", True, S + "SD-24 AclSize below its own 8-byte header")

AU = "S-1-5-11"; DOM = "S-1-5-21-1004336348-1177238915-682003330"
def user_default():
    p = lambda s: s
    a = []
    for m, t in ((0xF01FF, DOM + "-512"), (0xF01FF, "S-1-5-18"), (0x20094, "S-1-5-32-548"), (0x20094, "S-1-5-10")):
        a.append(ace(0, 0, m, t))
    for m, g, t in ((0x100, "ab721a53-1e2f-11d0-9819-00aa0040529b", "S-1-5-10"),
                    (0x100, "00299570-246d-11d0-a768-00aa006e0529", "S-1-5-10"),
                    (0x100, "a05b8cc2-17bc-4802-a710-e7c15ab866a2", "S-1-5-10"),
                    (0x30, "77b5b886-944a-11d1-aebd-0000f80367c1", "S-1-5-10"),
                    (0x30, "e45795b2-9455-11d1-aebd-0000f80367c1", "S-1-5-10"),
                    (0x30, "e45795b3-9455-11d1-aebd-0000f80367c1", "S-1-5-10"),
                    (0x10, "4c164200-20c0-11d0-a768-00aa006e0529", DOM + "-553"),
                    (0x10, "5f202010-79a5-11d0-9020-00c04fc2d4cf", DOM + "-553"),
                    (0x10, "bc0ac240-79a9-11d0-9020-00c04fc2d4cf", DOM + "-553")):
        a.append(ace(5, 0, m, t, obj=g))
    a.append(ace(0, 0, 0x20000, AU))
    for g in ("59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "037088f8-0ae1-11d2-b422-00a0c968f939",
              "bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "a1990816-4298-11d1-ade2-00c04fd8d5cd"):
        a.append(ace(5, 0, 0x10, AU, obj=g))
    a.append(ace(5, 0, 0x100, "S-1-1-0", obj="ab721a53-1e2f-11d0-9819-00aa0040529b"))
    a.append(ace(5, 0, 0x10, DOM + "-553", obj="5f202010-79a5-11d0-9020-00c04fc2d4cf"))
    a.append(ace(5, 0, 0x30, DOM + "-517", obj="bf967a7f-0de6-11d0-a285-00aa003049e2"))
    return sd(dacl=acl(a, rev=4), owner=sid(DOM + "-512"), group=sid(DOM + "-513")), a
UD, UD_ACES = user_default()
AU_INDEX = 13
dec("SD-26", UD, {"control": 0x8004, "owner": DOM + "-512", "group": DOM + "-513", "dacl": {"kind": "list", "rev": 4, "aces": [SUMMARY[x] for x in UD_ACES]}, "anomalies": [], "notes": ["acl.order_cosmetic@%d/r4" % AU_INDEX]}, False, S + "SD-26 User-class default order (shape of c-user defaultSecurityDescriptor, fixed fake domain SID, representative GUIDs): the spec's own default object must stay editable")
dec("SD-28", sd(dacl=acl([ace(9, 0, 1, SYS, tail=b"\x01\x02\x03\x04")], rev=2), owner=sid(SYS)), "acl.revision_type_mismatch", True, S + "SD-28 callback ACE in ACL rev 2")
dec("SD-29", sd(dacl=acl([ace(9, 0, 1, SYS, tail=b"\x01\x02\x03\x04")], rev=4), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 4, "aces": [ace_sum(9, 0, 1, SYS)]}, "anomalies": ["ace.callback_present@0"], "notes": []}, True, S + "SD-29 callback ACE in ACL rev 4: decoded, never evaluated")

X = "implementation hardening beyond §5.1: "
dec("SD-30", sd(dacl=acl([ace(0, 0, 1, SYS)], slack=b"\0\0\0\0"), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(0, 0, 1, SYS)]}, "anomalies": ["acl.zero_slack"], "notes": []}, True, X + "zero slack after the last ACE")
dec("SD-31", sd(dacl=acl([ace(0, 0, 1, SYS)], rev=3), owner=sid(SYS)), "acl.bad_revision", True, X + "ACL revision 3")
dec("SD-32", sd(dacl=acl([ace(0, 0, 1, SYS)]), owner=mut(sid(SYS), 0, b"\x02")), "sid.bad_revision", True, X + "owner SID revision 2")
dec("SD-33", sd(dacl=acl([ace(0, 0, 1, SYS)]), owner=sid(SYS)[:-4]), "sid.overrun", True, X + "owner SID claims one sub-authority more than is present")
dec("SD-34", mut(V01, 12, struct.pack("<I", 20)), "sd.sacl_offset_without_flag", True, X + "SACL offset with SP clear")
dec("SD-35", mut(V01, 2, b"\x14"), "sd.offset_out_of_range", True, X + "SP set with no SACL offset has no defined meaning: refused")
dec("SD-36", sd(dacl=acl([ace(0, 0x40, 1, SYS)]), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(0, 0x40, 1, SYS)]}, "anomalies": ["ace.unknown_flags@0"], "notes": []}, True, X + "audit-only AceFlags on an allow ACE")
dec("SD-37", sd(dacl=acl([]), owner=sid(SYS)), {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": []}, "anomalies": [], "notes": []}, False, X + "empty DACL is a list of zero ACEs, not NULL")
dec("SD-38", sd(sacl=acl([ace(2, 0xC0, 0x20, "S-1-1-0")]), owner=sid(SYS)),
    {"control": 0x8010, "owner": SYS, "dacl": {"kind": "absent"}, "sacl": {"kind": "list", "rev": 2, "aces": [ace_sum(2, 0xC0, 0x20, "S-1-1-0")]}, "anomalies": [], "notes": []}, False, X + "SACL with an audit ACE; DACL absent")
dec("SD-39", sd(dacl=acl([ace(0, 0, 1, SYS)]), owner=sid(SYS), control=0x8000 | 0x4000, rm=0x01),
    {"control": 0xC004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(0, 0, 1, SYS)]}, "anomalies": ["sd.rm_bits_set"], "notes": []}, True, X + "resource-manager bits set")
dec("SD-40", sd(dacl=acl([ace(0, 0, 1, SYS)], sbz1=1), owner=sid(SYS)),
    {"control": 0x8004, "owner": SYS, "dacl": {"kind": "list", "rev": 2, "aces": [ace_sum(0, 0, 1, SYS)]}, "anomalies": ["acl.sbz_nonzero"], "notes": []}, True, X + "non-zero reserved ACL byte")
dec("SD-41", sd(dacl=acl([ace(0, 0, 1, SYS), ace(0, 0, 2, SYS, size=8)]), owner=sid(SYS)), "ace.size_too_small", True, X + "second ACE too small")
dec("SD-42", sd(dacl=acl([ace(0, 0, 1, SYS, size=0x40)]), owner=sid(SYS)), "ace.size_overrun", True, X + "AceSize beyond the ACL")

# Control encoder
C = "safe-primitives-security-descriptor §5.2 "
def ctl(id_, parts, expect, hostile, src, cap=False):
    args = {"parts": {"hex": "%02x" % parts}}
    if cap: args["cap"] = {"utf8": "yes"}
    rec(id_, "ReadControl", args, expect, hostile, src)
ctl("SD-C01A", 4, {"bytes_hex": "3003020104"}, False, C + "SD-C01 DACL")
ctl("SD-C01B", 7, {"bytes_hex": "3003020107"}, False, C + "SD-C01 OWNER|GROUP|DACL")
ctl("SD-C02", 0, {"error": "sd.flags_empty"}, True, C + "SD-C02 the server treats 0 as 15")
ctl("SD-C03A", 8, {"error": "sd.sacl_requires_capability"}, True, C + "SD-C03 SACL alone")
ctl("SD-C03B", 15, {"error": "sd.sacl_requires_capability"}, True, C + "SD-C03 all four parts")
ctl("SD-C04", 0x14, {"error": "sd.flags_unknown_bits"}, True, C + "SD-C04 the server would ignore bit 0x10")
ctl("SD-C05", 15, {"bytes_hex": "300302010f"}, False, C + "capability issued (test-only token): SACL part encodes", cap=True)

# Helper
H = "safe-primitives-security-descriptor §5.2 "
X1 = "S-1-5-21-1004336348-1177238915-682003330-1105"
G1 = "S-1-5-21-1004336348-1177238915-682003330-1200"
def grants(id_, b, mask, expect, hostile, src, obj=None, user=X1, groups=(G1, AU, "S-1-1-0"), bare=None, objsid=None):
    args = {"sd": hexarg(b), "mask": {"utf8": str(mask)}}
    if bare is not None: args["sids"] = {"utf8": ",".join(bare)}
    else:
        args["user"] = {"utf8": user}; args["groups"] = {"utf8": ",".join(groups)}
    if obj: args["object"] = {"utf8": obj}
    if objsid: args["object_sid"] = {"utf8": objsid}
    rec(id_, "Grants", args, {"value": expect}, hostile, src)
def res(decision, sources=(), why=None, incomplete=False):
    d = {"decision": decision, "incomplete": incomplete, "sources": [{"ace": a, "inherited": i} for a, i in sources]}
    if why: d["why"] = why
    return d
OWN = sid(SYS)
inh_ace = ace(5, 0x12, 0x100, G1, obj=RP, inh=USER)
grants("SD-H01", sd(dacl=acl([inh_ace], rev=4), owner=OWN), 0x100, res("yes", [(0, True)]), False, H + "SD-H01 inherited copy on the child; GUID bytes 70 95 29 00 6d 24 d0 11 a7 68 00 aa 00 6e 05 29", obj=RP)
grants("SD-H02", sd(dacl=acl([ace(5, 0x0A, 0x100, G1, obj=RP, inh=USER)], rev=4), owner=OWN), 0x100, res("no", why="no_matching_ace"), False, H + "SD-H02 INHERIT_ONLY does not apply to its own object", obj=RP)
grants("SD-H03", sd(dacl=acl([ace(0, 0, 0x100, G1)]), owner=OWN), 0x100, res("yes", [(0, False)]), False, H + "SD-H03 no ObjectType: all extended rights", obj=RP)
grants("SD-H04", sd(dacl=acl([ace(5, 0, 0x20, G1, obj=RP)], rev=4), owner=OWN), 0x100, res("no", why="no_matching_ace"), True, H + "SD-H04 inert ACE: right GUID with a property mask", obj=RP)
grants("SD-H05", sd(dacl=acl([ace(0, 0, 0x20, "S-1-5-10")]), owner=OWN), 0x20, res("unknown", why="self_unresolved", incomplete=True), True, H + "SD-H05 SELF without a SelfSID", bare=[G1])
grants("SD-H05B", sd(dacl=acl([ace(0, 0, 0x20, "S-1-5-10")]), owner=OWN), 0x20, res("yes", [(0, False)]), False, H + "SD-H05 SELF when the object is the principal itself", objsid=X1)
grants("SD-H06", sd(dacl=acl([ace(9, 0, 0x20, G1, tail=b"\0\0\0\0")], rev=4), owner=OWN), 0x20, res("unknown", why="callback_ace"), True, H + "SD-H06 callback conditions are not evaluated")
grants("SD-H07", sd(dacl=acl([]), owner=OWN), 0x100, res("no", why="no_matching_ace"), False, H + "SD-H07 empty DACL grants nothing")
grants("SD-H07B", sd(dacl=acl([]), owner=sid(X1)), 0x40000, res("unknown", why="implicit_owner_rights"), False, H + "SD-H07 owner keeps implicit WRITE_DAC: Unknown")
grants("SD-H07C", mut(V01, 16, b"\0\0\0\0"), 0x100, res("yes", why="null_dacl"), False, H + "SD-07 NULL DACL: Yes for every right")
grants("SD-H08", sd(dacl=acl([ace(0, 0, 0x20, G1)]), owner=OWN), 0x20, res("no", why="no_matching_ace", incomplete=True), True, H + "SD-H08 group grant, principal without tokenGroups", groups=())
grants("SD-H05C", sd(dacl=acl([ace(0, 0, 0x20, "S-1-5-10"), ace(0, 0, 0x20, G1)]), owner=OWN), 0x20, res("yes", [(1, False)]), False, H + "SD-H05 an unresolved SELF allow does not hide a definite grant")
grants("SD-H05D", sd(dacl=acl([ace(0, 0, 0x20, "S-1-5-10"), ace(1, 0, 0x20, G1)]), owner=OWN), 0x20, res("unknown", why="self_unresolved"), True, H + "SD-H05 an unresolved SELF allow before a deny: the deny might not be reached")
grants("SD-H09A", UD, 0x20000, res("yes", [(AU_INDEX, False)], incomplete=True), False, H + "SD-H09 Authenticated Users read-control through the (A;;RC;;;AU) ACE", bare=[AU], objsid=G1)
grants("SD-H09B", UD, 0x10, res("no", why="no_matching_ace", incomplete=True), False, H + "SD-H09 a property the AU ACEs do not name", obj="11111111-2222-3333-4444-555555555555", bare=[AU], objsid=G1)
grants("SD-21H", sd(dacl=acl([A, D]), owner=OWN), 0x20, res("yes", [(0, False)]), True, H + "SD-21 helper evaluates in stored order: allow first wins", user=X1, groups=(G1, "S-1-5-32-545"))
grants("SD-H10", sd(dacl=acl([D, A]), owner=OWN), 0x20, res("no", [(0, False)]), False, H + "canonical order: deny first refuses", user=X1, groups=(G1, "S-1-5-32-545"))
grants("SD-H11", sd(dacl=acl([ace(0, 0, 0x20, G1), bytes([0x7F, 0]) + struct.pack("<H", 16) + b"\0" * 12]), owner=OWN), 0x10, res("unknown", why="opaque_ace_present"), True, H + "SD-19 opaque ACE: Unknown rather than No")

with open("testdata/safe-primitives/sd.read.jsonl", "w") as f:
    for r in recs:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")
print(len(recs), "records,", sum(1 for r in recs if r["hostile"]), "hostile")
