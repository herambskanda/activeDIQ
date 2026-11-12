---
name: sync-mapper-lessons
description: T-1189 sync mapper — connector allowlist gap, DnValue has no guid today, Samba UAC 546, lab capture recipe
metadata:
  type: project
---

- The connector's request allowlist is `ad.DefaultSchema()`; a name outside it is `INVALID_ARGUMENT "invalid request"` (no field named). 12 closed-list attrs were missing (T-1203). Lab tests widen their own session with `newSearchLabSchema(t, extra)`; do not widen the product allowlist inside an unrelated ticket.
- `DnValue.guid/sid` is NEVER set by today's connector (no extended-DN control; T-1202). Real group entries map with 0 edges + `MembersUnresolved`. Positive member paths are covered by synthetic GUIDs and the Populate test only.
- Connector emits attribute names lowercased; index case-insensitively.
- `objectClass=user` also returns computers: pick lab objects by CN, not by class.
- Samba: an LDAP-added user without a password has UAC 546 (disabled). Derive expectations from the fixture, don't assume enabled.
- Absent attribute = not read (bit clear). Present-but-empty = read. Connector omits requested-but-missing attrs (T-1204), so never-locked users stay Unknown.
- Fixture recapture: `SYNC_CAPTURE_DIR=$PWD/internal/directory/sync/testdata/lab go test -tags lab ./internal/connector/read -run TestLabSyncMapping` (reads lab/.lab.env itself; lab-up ≈ 6-9 min). Golden test reads expectations off the entries, so a new stamp is fine.
- Pre-existing red, not yours: `go run ./tools/fitness/modules` (33), vettool RP1 in inventory/datasets_groups.go.
