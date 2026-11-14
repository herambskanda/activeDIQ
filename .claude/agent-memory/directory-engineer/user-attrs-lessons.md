---
name: user-attrs-lessons
description: T-1111 — user-attribute sync set, migration needs FORCE RLS lift, new bag keys flood change history, lab test recipe
metadata:
  type: project
---

- Sync-set growth = three edits: `connector/ad/schema.go` (name-only entries), `sync/attrs.go`, mapper `userAttributes`; columns in `inventory/datasets.go` (`userAttributeColumns`). Bag is JSONB, so no column migration.
- Existing objects only gain new keys via a full read: migration 0078 sets incremental `sync_cursors` to resync_required. Migration owner sees zero rows under FORCE RLS; lift with `NO FORCE` for the one statement (as 0021/0047/0074).
- Photos: mapper keeps only `hasThumbnailPhoto/hasJpegPhoto` true; bytes are still transferred by the connector (no presence-only mode).
- Hazard filed as T-2018: new bag keys on resync make `chg` CTE write 'edited' rows. T-2019 direct reports, T-2020 Windows lab Lync.
- Samba: no msRTCSIP-UserEnabled schema. TestLabSyncMapping/group is red on main (T-1202 resolves members now).
- Lab test: `make lab-up` 453s; `go test -tags lab ./internal/connector/read -run TestLabUserAttributes`. Full sync pkg `go test` exceeds 4 min here: use -run.
