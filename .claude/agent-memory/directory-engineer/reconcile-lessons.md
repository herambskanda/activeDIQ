---
name: reconcile-lessons
description: T-1196 reconcile pass — runtime role can't CREATE TEMP, fake prescan heuristic, usersOf indexes, unmerged dependency branches
metadata:
  type: project
---

- Runtime role cannot `CREATE TEMP` (ADR-0002 rule 4, store_test.go:390): diff GUID sets in Go (`map[[16]byte]struct{}`, 16 B/object) inside the tx, not via a temp table or a 200k-uuid array.
- The sync fake's prescan heuristic is `len(attrs) <= 2`; a one-attr (objectGUID) listing needed its own `listing` flag in `engine_fake_test.go`.
- `usersOf(fo, ncA, 0..599)` are members of the Big group; use index >= 610 for non-members. Closure of H (G + u3) is 4 rows.
- Mutation checks that proved the tests bite: drop the list-error return, drop the share test, diff per-NC instead of forest-wide — each fails exactly the AC test.
- Depended-on branches (T-1189/1190/1191) were `done` but not merged to main: merge them into the ticket branch first.
- Running sync + inventory tests together blows Go's default 10 min timeout; run separately with `-timeout 30m`.
