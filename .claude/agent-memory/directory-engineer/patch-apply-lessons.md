---
name: patch-apply-lessons
description: T-1197 patch apply — link edge direction, permutation test cost, mutation check recipe, sync test fixtures
metadata:
  type: project
---

- `links` edges run **group (source) -> member (target)** for both `member` and `primary_group`; `GroupsOf` walks target->source. A test that looks for `source = user` finds nothing.
- `gtext(n)` is hex: `gtext(80)` ends `…50`. Count objects in a dump by hand (head, OUs, users, groups) before choosing a threshold.
- One 8-change apply is 60-120 ms on pg18/pg16, so 8! permutations (~1-2 h) is out. The shipped shape: exhaustive over the six dependent changes (720), 80 seeded random orders of all eight, reversed, and multi-batch / one-change-per-batch splits (~80 s per PG version).
- The tenant role cannot DELETE `directory_objects`/closure rows: reset a fixture by using separate GUIDs, or `applyRolledBack` (apply + dump in a tx that returns a sentinel error).
- Mutation-check a permutation test by neutering one SQL step (I replaced the `belowSQL` Exec with `SELECT 1`): it fails on the first order. Back up the file first; a test run that exceeds 120 s moves to the background and the restore step runs only when it ends.
- `Mapper.index` drops attributes not on the closed list, so `unicodePwd` in a change leaves no trace without any special-casing.
- Tests that dump `to_jsonb(d)` compare every column, including `inputs_read` and `ancestry_complete`; drop `observed_at` when the as-of differs between runs.
