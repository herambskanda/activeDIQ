---
name: sync-cursor-lessons
description: T-1190 sync_cursors store — fitness traps (tenant_id in identity trigger, SQL const rule, platform_leases in tests), fencing design limits
metadata:
  type: project
---

- fitness-tenancy T4 `write-cross-tenant` expects RLS to reject a tenant re-assignment: a guard trigger must NOT test `tenant_id` (it fires first with AD403).
- safeprim FF-SP2: `tx.QueryRow/Exec` needs a constant SQL argument at the call site; a helper taking `sql string` is a violation. Keep the SQL const in each method and pass the `pgx.Row` to a shared `written()`.
- Tests may not name `platform_leases` (T5 global-table-sql) nor use `WithPlatform` (with-platform-site). Lapse a lease with a 100 ms TTL + sleep; get a no-tenant tx via `d.App(ctx)` + `Begin`.
- Store cannot check lease liveness (only `jobs` names the table): fencing = stored-token CAS + `Claim` at acquisition. Document: renew before the commit that matters.
- RequireResync must exclude `paused` from its allowed-from set even though paused→resync_required is legal (only ResumeConnection resumes) — the all-states × all-ops matrix test caught it.
- No doc.go in directory/sync from this ticket: T-1189 owns it (parallel ticket).
- Package is named `sync`: tests import it as `dsync`; never import std `sync` in the same file.
