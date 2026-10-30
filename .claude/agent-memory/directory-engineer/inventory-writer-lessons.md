---
name: inventory-writer-lessons
description: inventory writer/gate/designation lessons — fitness-tenancy FK probe, Action inverse shape, pre-existing red
metadata:
  type: project
---

- Operation `Inverse` returns an input to the SAME Action ID, so add/remove pairs must be one Action with a `designated bool` input (flip it for the inverse).
- fitness-tenancy FK probe with two keys to one parent: needs sibling FKs pointed at an alt parent row (`rowWithSiblingFKs` in synth.go); the tenant column must be excluded when testing whether two FKs share columns; a CHECK that makes the two columns differ needs a `probeValues` entry for one of them.
- Pre-existing red (not ours): duplicate migration numbers 0005/0007 (T1), fleet_ca/hybrid_links probe-seed, tenant-id-minting in fleet, fitness-api A7 json v1, fitness-stack F2 dial.
- Postgres tests use docker (works here); `storetest.EachVersion` runs pg16+18, ~25s per package.
- principal IDs are strings, not uuids: store `designated_by/removed_by` as text.
