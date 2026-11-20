---
name: read-marker-lessons
description: T-2216 — user attrRead marker semantics, enum label trap, slow inventory tests
metadata:
  type: project
---

- Wire cannot tell denied from empty; marker is observed/not_observed only, derived from the stored bag (empty value = not_observed). unknown_denied reserved for T-2220 DACL spike.
- Marker lives at attributes.attrRead (full-read Mapper only; ChangeMapper has no user attrs). New bag key => resync writes 'edited' history rows (T-2018).
- Report enum columns need every value in `enumLabels` (datasets.go) or registry build fails for ALL inventory tests.
- `go test ./internal/directory/inventory -run Test_reports` exceeds default 10m timeout: pass -timeout 40m.
