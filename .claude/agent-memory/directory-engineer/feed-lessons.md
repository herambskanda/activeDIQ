---
name: feed-lessons
description: T-1194 ChangeFeed RPC - Samba cn/result-200 quirks, golden-list Feeder trap, pre-check order, lab recipe
metadata:
  type: reference
---

- Samba DirSync never sends `cn` (the RDN arrives as `name`); requested ordinary attrs (sAMAccountName) do, on live and tombstone alike. Consumers key on `name`; Windows behaviour is for T-1282.
- go-ldap reports a dead/closed connection as `*ldap.Error` result 200 (`ldap.ErrorNetwork`), not a transport error: `searchRaw` used to call it PROTOCOL_ERROR, so an issuer-down resume came back PROVIDER_FAILURE instead of UNREACHABLE_DC. Fixed; classify on result code only.
- `ManagesNC` runs before `BoundDC` in the handler, so any directory read in the early path must map through `feedFailure` (resume => SAME_DC_AFTER_BACKOFF), never raw `mapAD`.
- A source that is not a `read.Feeder` answers CAPABILITY_UNSUPPORTED, which grpcCode maps to Unimplemented: the tunnel golden-list test needs a Feeder fake (`fakeSrc` in mount_test.go) or ChangeFeed looks unmounted.
- Garbage `provider_state` on Samba is rejected with result 2 or 12 and `cookieRejection` catches it (CC-FEED-11 passes); Windows code 0000203D unverified (T-1282).
- Lab recipe: `go test -tags lab ./internal/connector/read -run TestLabFeed -v -timeout 10m` (~15 s); server AC5: `go test -tags lab ./internal/compose/server -run TestLabServerServesChangeFeed` (~90 s, two PG versions). Relay tests need the cert's 127.0.0.1 SAN.
- Pre-existing red, not ours: `tools/fitness/api` TestFixtureEnvIsClean (needs `make web-install` for ajv), `compose/server` TestBootReportSealsHost (inventory.principals dataset from T-0962), safeprim 3 inventory violations.
