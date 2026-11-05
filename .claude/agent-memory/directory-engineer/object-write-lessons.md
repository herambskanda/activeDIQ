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
