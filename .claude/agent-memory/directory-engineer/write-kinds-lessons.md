---
name: write-kinds-lessons
description: T-1623 kinds 1-3 (object create/update/delete) - shared codec, test substitution traps, schema allow-list, lab recipe
metadata:
  type: reference
---

- Digest conversion lives in `internal/directory/writechange` (shared by client and connector); a client fixture must use its encoded names (`set:description`, value `s:new`) and an empty `Target.Class` for kinds 2/3.
- shapeCheck (arm vs kind) runs at step 1, so any test that substitutes `h.ops` at kind 1 must send `testChange()` (helpers_test.go) or it is refused WriteChangeArmMismatch.
- `ad.Tx` is concrete: no fake ObjectDirectory for the body. Unit-test the pure parts (`prepareEdits`, `vetCreateFields`, `shapeCheck`, declarations) with a fake `EditableAttr`; the bodies are lab tests (`wk_lab_test.go`).
- The default `ad.DefaultSchema()` allow-list is tiny; `manager`, `title`, `directReports` need `Config.Schema = DefaultSchema().With(...)`.
- A nil `*tier0.Set` PropertyGuard refuses every write: lab rigs build one from `graphtest` + `tier0.New(c).Snapshot`.
- `internal/directory/sync` tests hang ~6 min without a DB (pre-existing); run `./internal/directory/client ./internal/directory/writechange ./internal/connector/...` instead.
- `make lab-up` in a fresh worktree: image build + provision + seed ~10 min; `lab/.lab-ca.pem` appears last.
- T-1632: `WriteOp.PropertyWrite` sees only the typed change, never the live class. A kind whose verdict depends on class (delete) declares at step 4 and repeats the check in the body via `Authorised.checkProperty` with the live class; test both halves, and mutation-check the body call (unit tests alone do not prove the body calls it).
- `newWKRigRuleText(t, rule)` builds the lab rig with any Entra dynamic rule; `git checkout <file>` during a mutation check reverts UNCOMMITTED real edits too, so commit first.
- T-1632 review: deleting a manager clears its reports' `manager` (MS-ADTS 3.1.1.1.6), so "only a group delete touches other objects" was false; guard premises from a spec row need a lab attack. `directReports` is now in `DefaultSchema`. `ad.Tx` is concrete, but a body can take a small interface (`deleteTx`) so Plan/Apply bodies get non-lab tests; CI runs no `-tags lab`. A recheck returns the `*Refusal` (reason/kind/op fields copied into the Event by `finish`), not a bool. `sAMAccountName` is unique per domain: loop-created lab users need a suffix.
