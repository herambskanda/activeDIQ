---
name: sd-tree-lessons
description: T-1731 — sd.Grants attribute object-type tree (Right.Tree), test-fixture traps, no Windows lab on the dev box
metadata:
  type: reference
---

- Attribute asks pass `Right.Tree = &ObjectTree{Class, Set, Catalog}`; `Object` is the attribute GUID. Tree checks (nil/unplaced class, set, attribute, catalog, duplicate GUIDs, mask beyond RP/WP) answer Unknown BEFORE the DACL walk, NULL DACL included. No Tree = old `property_set_unresolved`.
- Object ACEs in test DACLs need ACL revision 4 (`encodeDACLSD(0, 4, ...)`), else `acl.revision_type_mismatch`. `encodeNew` checks mask-vs-kind via the catalog: encode with an `anyKind` catalog to make class-GUID/unresolvable-GUID ACEs.
- `mapCatalog` (write_test.go) and `mustGUID` are the shared test helpers in package sd.
- No KVM/virsh and no `.win-lab.env` on the dev box: Windows-lab AC cannot run here; file a test ticket (T-1758 for this one).
- The corpus (`sd.read.jsonl`) has no tree records; adding some needs `tree_*` args in `grantsRecord` and the Python generator.
