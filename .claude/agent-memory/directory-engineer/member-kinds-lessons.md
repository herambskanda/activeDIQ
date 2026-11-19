---
name: member-kinds-lessons
description: T-1586 kinds 11-13 — where the connector/client halves live, test-helper name clashes, unimplemented spec items
metadata:
  type: project
---
- Kind 13 is in `accountkind.Specs()`; kinds 11/12 are in `accountkind.GroupSpecs()` (a separate list so account-only tests keep working). Group digest target class label is `group`; member GUID + class are digested attrs.
- Kinds 11/12 body uses `ad.Tx` through a `memberTx` seam (`kinds_member.go`), the same trick as `deleteTx`; Tx.Read does not follow ranges.
- Unit-test helpers `sidBytes`/`grpDN` already exist in `write` tests; fake `AccountSession` with `secure=false` answers TRANSPORT_SECURITY before the class check.
- Not implemented (spec only): `guarded.ComputerReset()`/B1/GM3 (no `guarded` package), C20 refusals, Plan-time Write-property `member` rights probe.
- sync tests hang without a DB: never run `./internal/directory/...` wholesale.
