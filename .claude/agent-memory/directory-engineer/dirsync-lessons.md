---
name: dirsync-lessons
description: T-1193 DirSync primitive - Samba DirSync facts (tombstones need admin, show-deleted not needed), design choices, lab test recipe
metadata:
  type: reference
---

- Samba DirSync: the plain `svc-activediq` identity sees live changes but NO tombstone; Administrator sees them. Samba returns deleted objects even without show-deleted, so only the wire-capture test (CC-FEED-23) proves the control is attached.
- One Samba cycle = one response (MoreData never set). Removed member = `member;range=0-0`, added = `range=1-1`. `parentGUID` arrives on create/rename/move when `name` is requested, not on a plain modify. Cleared attribute = name with no values. Unrequested secrets never arrive, so the strip counter can only be proven in unit tests (decodeChange).
- AD wants DirSync flags as a 4-byte unsigned INTEGER: hand-encode (copy go-ldap's ControlDirSync.Encode); go-ldap's request type accepts any flags so never use it for requests. Response decode via `*ldap.ControlDirSync` (Flags = MoreData).
- `DefaultSchema` lacks pwdLastSet/lastKnownParent: lab tests extend it with `Schema.With` via `Config.Schema`.
- DirSync must go through `searchRaw` (not searchOnceLocked): the latter prepends domain-scope, breaking "no other control".
- Lab raw DNs in tests need `\+` and `\,` escaped by hand; prime of the 7k-object lab is ~1.7 s.
- Capture proxy for wire assertions: tls relay + ber.ReadPacket on client side, parse Children[2] controls (see dirsync_lab_test.go).
- safeprim scanner full run is red on 3 pre-existing inventory violations (datasets_groups.go) - not ours.
