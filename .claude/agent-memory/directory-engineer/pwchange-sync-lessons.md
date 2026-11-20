---
name: pwchange-sync-lessons
description: T-1551 sync wiring of Cannot Change Password — no RPC existed, new Read verdict field, test-fake memory trap, lab ACE-write recipe
metadata:
  type: reference
---

- The sync only has `client.Reader` (Describe, ScopedSearch); T-1551 added `Read` to it (update `TestReaderIsReadOnly` want-list) and `ReadRequest.include_password_change=17` / `ReadHeader.password_change=5` (verdict, never SD bytes). Connector side is the optional `read.PasswordChanger` source half, so existing `read.Source` fakes keep compiling.
- Regenerating one pb.go without protoc: protocompile driver -> CodeGeneratorRequest -> `protoc-gen-go` binary -> decode CodeGeneratorResponse (see replstatus-lessons). Comment-only edits can be hand-made in both .proto and .pb.go (descriptor has no comments).
- Engine test fake must not retain per-object Read requests unbounded: `TestFullCycleMemoryIsBounded` (100k users) went 9 -> 40 MiB because of the fake, not the engine. Cap the recorded slice.
- Full `go test ./internal/directory/sync` takes ~6 min (Postgres containers); run it in the background.
- Lab test for deny ACEs from package `read_test`: second `ad.Open` as Administrator, `ReadDACL` + `sd.PlanDACL` + `WriteDACL(…, ops.ReplaceSD)`; the GUID for the plan must be the raw mixed-endian `guid.FromBytes(objectGUID)`, NOT the wire (RFC-order) GUID or WriteDACL says "object is not the one the plan was made for".
- Fake upstream (`startFakeUpstream`, `up.sdAttrs`, `up.searchLog()`) records control OIDs: used to assert the SD_FLAGS control (1.2.840.113556.1.4.801) on the wire; the domain-scope control 1339 rides along, so assert Contains, not equality.
