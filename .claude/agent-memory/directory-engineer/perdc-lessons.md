---
name: perdc-lessons
description: T-0970/T-1143 per-DC read - handler shape, no 2dc lab yet (T-1529), opener closure holds the credential, coverage derived not trusted
metadata:
  type: feedback
---

- T-1143 (wiring: backend.go opener = ad.Open with Servers=[host]; mount.go tunnelServer.ReadPerDC; golden list in mount_test is 6) landed `read.Handler.ReadPerDC` (perdc.go); `PerDCSource` is the optional Source half, `ADPerDCSource` needs an `OpenFunc` because `ad.Session` never keeps the credential. Per-DC client tests run over a real bufconn gRPC hop with a scripted `ConnectorServer` (perdc_test.go `pdServer`), not Samba.
- Coverage is derived from accepted answers; the connector's COMPLETE is never raised above them. A DC with missing/mistyped values is an errored result (`incomplete_values`/`invalid_value`), never a skipped one.
- Per-tenant bound = a semaphore per tenant held on the reader, shared by every Read call; acquire with `select` on ctx and never drain a token you did not take.
- ObjectID -> wire Guid is `wireGUID` (usersearch.go); canonical text of an ObjectID = `formatUUID(wireGUID(id).Value)`.
- Lab has ONE Samba DC (no 2dc profile; T-1529): CC-PDC-03/04/05 are unproven on Samba; CC-PDC-06 is T-1530. Counters/caps live on the Handler (limiter keyed by DSA GUID / NC GUID), shared across calls.
- Absent lastLogon/logonCount = ZERO/0 (a never-logged-on user); an unreadable attribute looks the same - residual risk, rights are the connection's.
