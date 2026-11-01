---
name: sync-engine-lessons
description: T-1191 full-read engine — test-rig traps (RLS owner updates, leases, activation), design choices, what is still unbuilt
metadata:
  type: project
---

- `d.ExecOwner` on a tenant table (forced RLS) updates 0 rows with no error. Take a test connection to active through the real lifecycle (`Registry.Transition` → `SetDirectoryIdentity` → `Store.RecordVerification` + `Activate` in a tenant tx, see `engine_test.go` `activate`).
- A platform lease is not re-acquirable by the same holder while live: release the old one first (`jobs.ReleaseLease`) to get a fresh, higher token. Reuse one rig across loop cases; a failed run leaves its leases held.
- `store.Tx` can be nil in DB-free engine tests (fake Tenants calls `fn(ctx, nil)`): engine memory is measured in `engine_mem_test.go` (≈6 MiB growth at 100k objects, pre-scan link map only).
- One lease and one cursor per NC (`Lease.Name` must equal `LeaseName(Key)`), so FullCycle takes a `LeaseFunc`, not a lease. A cursor that is already incremental is skipped.
- `CompleteScan` leaves NO cookie; incremental + no cookie = "prime the feed" (DirSync ticket must handle).
- Errors never wrap the gRPC error (its text may hold a DN): keep only the code (`ConnectorError`).
- Tests are fake connector + Postgres only. Not proved on Samba or Windows; ranged `member`, `SchemaSecrets` and `DnValue.guid` (T-1202) are real-connector gaps.
- A running read must re-check the connection every batch (`Conns.Get` + `refuse`) and the cursor (`StatePaused`) in the batch tx; `wrap` must pass `ErrPaused`/`ErrRefused` through so a stop aborts the cycle, not one domain. Decommissioning sets RetiredAt, so its refusal reason is `retired`. Never log `err.Error()` of a store error (`errClass`).
