---
name: attestation-wiring-lessons
description: T-0440 TM-D17 wiring — apihost path-param bug, A6 net/http rule, AN allow-list, fake Microsoft TLS server pattern
metadata:
  type: project
---

- apihost used `mux.Handler(r)` then `h.ServeHTTP`, which never sets `r.PathValue`: every path-param route got "required parameter missing". Fixed to `mux.ServeHTTP` (T-0440); the connections HTTP e2e test is the guard.
- Fitness A6: anything under `internal/modules/**` is a "handler package" and may not import `net/http`. HTTP adapters for module ports live in `internal/compose/server/<x>`.
- Fitness A7: `encoding/json/v2` only (`jsontext.Value` replaces `RawMessage`). A new AN-n row also needs `tools/fitness/api/a3.go` allow-list, the fixture policy rows in `check_runtime_test.go`, and the `policy_test.go` fixture in compose.
- Generator: no `x-activediq-scope: tenant` (default), no `format: int64`; needs `make web-install` first. BodyNone ops reject any body (413) and PUT without JSON content-type is 415 before authn.
- Fake Microsoft: one `httptest.NewTLSServer` serves token + Graph; verify PKCE (sha256 of verifier == challenge from the authorize URL) and the Bearer on the read. Give the Attester `Now: e.now` or a real-time attestation reads "stale".
- Pre-existing red (T-0476): stepUpTable lacks correlation.reconfirm; json v1 in inventory/objects.go, apitls, audit/jobs.go.
