---
name: tokenset-lessons
description: T-1741 rights TokenSet export — where it lives, epoch rules, test fixture traps
metadata:
  type: reference
---
- `rights.TokenSet` is built in `adCheck.exportTokens` from the single identity read (sIDHistory added to that read); recorded only by `EpochState.CompleteWithTokens` for a PASS run. `Complete()` is the old signature (nil tokens). Accessor `EpochState.TokenSet()`; memory-only, so ok=false after restart.
- sIDHistory also joins `c.tokens`/`c.own` of the check (real tokens hold it): a Domain Admins SID in history now fails V7.
- `PrincipalFromTokenSet` is in `rights`; it wraps new `sd.PrincipalFromSIDSet(sids, complete)`. The accessor is not yet wired into `internal/connector/read` (T-1566).
- Fixture trap: `world.putRaw` copies only a whitelist of attribute keys; add new attributes there or they silently vanish on the next put.
- `go test ./internal/compose/...` takes >5 min and `compose/server` failed with no `--- FAIL` line in this worktree (DB/job-worker output); not touched by this change. Run `./internal/connector/... ./internal/directory/sd/` instead.
