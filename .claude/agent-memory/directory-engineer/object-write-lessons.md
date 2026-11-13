---
name: object-write-lessons
description: T-1624 move/rename/restore lab traps (Samba ModifyDN, Recycle Bin, GUID entry)
metadata:
  type: project
---
- Samba ModifyDN with unchanged RDN needs deleteoldrdn=true ("Old RDN must be deleted"); false is refused.
- Samba rejects a `<GUID=>` entry in ModifyDN: address by the DN read under the same lock.
- Samba has no Recycle Bin: restore is CAPABILITY_UNSUPPORTED; ClassifyDeleted only provable on Windows (T-1640).
- Lab write tests need `prov.Dynamic = &stubGuard{}` or every write is CUSTOMER_DESIGNATED.
- To debug an opaque PROVIDER_FAILURE, temporarily print the err in mapWriteErr.
- TM-D33 step 7 (kind 6): Samba returns the Deleted Objects container (WKGUID, show-deleted) WITHOUT nTSecurityDescriptor even to Administrator, so the grant never proves on Samba (fail closed, INSUFFICIENT_RIGHTS); only Windows proves it (CC-WK-32..35).
- Plan runs step 7 before the op's Plan: check the Recycle Bin flag first inside ClassifyDeleted or Samba restores answer INSUFFICIENT_RIGHTS instead of CAPABILITY_UNSUPPORTED.
- `ad.Read` range follow-ups must carry the deleted controls (417+2065) too; show-deleted is now critical (encodeCriticalValuelessControl).
- write cannot import rights (rights imports write): schema GUIDs for the Read Property proof come from Dir.Find on the Schema NC.
- ADProvider.Self (connection identity ref) must be set by the composition root; unset means restore is refused.
- Unit-test SDs: hand-build a self-relative SD (header 20 bytes, DACL at 20) — see buildSD in deleted_test.go.
- Security review T-1624: kinds 4-6 declare PropertyWrite as USER and DEVICE (`WriteOp.AlsoDevice`); R2 bases (C4/C8/C12/C14) are checked on present values, not just proven readable; primary group 513-515 judged like memberOf; no exported show-deleted option in `ad` (only fixed-shape fns in deletedread.go); deleted DN parent must equal the container DN typed.
- Test descriptors (buildSD) need an owner now; refDir fake needs bySID for primary-group lookups.
