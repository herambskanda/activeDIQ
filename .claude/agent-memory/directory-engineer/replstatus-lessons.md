---
name: replstatus-lessons
description: T-1723 ReadReplicationStatus - no protoc recipe, controls bypass, fake-upstream rootDSE, RX6 comment trap
metadata:
  type: feedback
---

- No protoc/buf here: build protoc-gen-go (`go build google.golang.org/protobuf/cmd/protoc-gen-go`) and protoc-gen-go-grpc (`GOFLAGS=-mod=mod GOPROXY=off go build google.golang.org/grpc/cmd/protoc-gen-go-grpc`), drive them from a throwaway Go main using protocompile (`SourceInfoStandard`) -> CodeGeneratorRequest, `paths=source_relative`. Output is byte-identical to the committed pb.go for untouched files; delete the driver afterwards.
- `searchOnceLocked` adds the domain-scope control to every search; a "no control" read must use `searchRaw` directly (ReadReplication does).
- RX6: the strings repsFrom/repsTo may not appear in ANY non-test Go file of internal/connector, comments included.
- Test helper name `request` collides with the handler's `request` type; the fakeUpstream (ad/ldapfault_test.go) now serves msDS-Repl* rootDSE attrs, ranges, denial, and records every search + controls.
- A DC with nothing to say still returns the rootDSE entry (zero attrs); tolerate 0 entries as "not returned" too.
- No DC enumeration exists in the connector (Describe DC section not built): replstatus works over DCLister/Opener seams; Bound = one session. Multi-DC lister is follow-up work.
