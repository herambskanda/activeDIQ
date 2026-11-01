---
name: perdc-lessons
description: T-0970 ConnectorPerDC - no connector ReadPerDC handler exists, scripted bufconn server pattern, coverage derived not trusted
metadata:
  type: feedback
---

- `internal/connector/read` serves Read/ScopedSearch only; ReadPerDC is generated but unimplemented (follow-up T-1143). Per-DC client tests run over a real bufconn gRPC hop with a scripted `ConnectorServer` (perdc_test.go `pdServer`), not Samba.
- Coverage is derived from accepted answers; the connector's COMPLETE is never raised above them. A DC with missing/mistyped values is an errored result (`incomplete_values`/`invalid_value`), never a skipped one.
- Per-tenant bound = a semaphore per tenant held on the reader, shared by every Read call; acquire with `select` on ctx and never drain a token you did not take.
- ObjectID -> wire Guid is `wireGUID` (usersearch.go); canonical text of an ObjectID = `formatUUID(wireGUID(id).Value)`.
