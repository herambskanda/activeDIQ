---
name: perdc-count-lessons
description: T-1499 DCsInScope - Describe-based DC count, wiring through directory.Services.PerDC, reports pkg tests hang without Postgres
metadata:
  type: feedback
---

- DCsInScope counts from Describe(refresh): scope all = every DC of the domain (RODC, unreachable included); writable = not proven RODC (UNKNOWN counts). Needs `PerDCConfig.Describe`, else ErrNoDescribe.
- Wiring: `directory.Services.PerDC *client.ConnectorPerDC` -> reports wiring sets run.Service.PerDC and PerDCDCs (guard the nil pointer, a typed nil in an interface defeats job.go's nil check).
- `go test ./internal/modules/reports/` hangs in TestMain here (no Docker/Postgres); only vet it locally.
- Connector-side ReadPerDC is still unimplemented (T-1143): per-DC runs wire up but fail at the read.
