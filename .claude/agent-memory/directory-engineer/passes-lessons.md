---
name: passes-lessons
description: inventory per-NC sync pass watermark (T-0949) — what Freshness derives vs stores, test setup traps
metadata:
  type: project
---

- `nc_sync_passes` stores only ok/resync_required/paused; a suspended connection's pause and "never synced" (no row, or NULL `last_pass_at`) are derived in `Reader.Freshness`, not written.
- Pass as-of = `Cycle.Observed` (start of read). A quiet DirSync cycle must still list `Cycle.PassNCs` or the NC goes stale; no sync caller exists yet (follow-up ticket).
- Test helper name `oid` is taken by tm_f_hybrid_test.go (`ncOID` here). Activating a connection in tests needs a RecordVerification pass row first (copy the passes_test `suspend` helper).
- Full inventory package test takes ~190 s on pg16+18; run `-run` filters while iterating.
