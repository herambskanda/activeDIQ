---
name: printers-lessons
description: T-1719 — printqueue kind needs two CHECK widenings + resync, OU path is the dn column (RP11), lab seed must not shift rng, LDIF base64 DNs
metadata:
  type: project
---

- New object kind = Kind const + validKinds + mapper kindOfClass + migration widening BOTH `directory_objects_kind_check` and `directory_object_changes_object_kind_check` + cursor resync (copy 0081). Existing rows of the class were stored `other`; the full read reclassifies them.
- A derived "OU path" column fails RP11 (sentinel parent OUs outside the dn cell). Convention is `ou_path_is_dn`: use the `dn` column. Every dataset needs an RP11 world in `Test_dataset_reveals_nothing_outside_scope` (default branch Fatalf) and an entry in compose/server boot_internal_test dataset list.
- Class-specific attributes (printQueue `location`) are mapped only when kind matches, so a computer's `location` never enters the bag or the change history.
- Lab seed: add objects without drawing from `rng` (later objects keep their place) and load in the parent's aged bucket. Non-ASCII DNs are `dn::` base64 in LDIF: compare via `generate.ldif_value`.
- Samba accepts printQueue under a computer if printerName, serverName, shortServerName, uNCName, versionNumber are set. `go test ./internal/directory/sync` whole package hits 600 s: use -run. Lab-up 375 s.
