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
