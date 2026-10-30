# credprov-spike

- **OWNER:** windows-engineer
- **TICKET:** T-0147
- **EXPIRES:** 2027-01-31. After that, delete it; learnings live in `knowledge/product/specs/credential-provider.md`.
- **QUESTION:** are the three TM-F-CREDPROV rules (pinned server only, offline never blocks logon, no web/shell-dialog
  imports) expressible as small, testable decision logic before any COM/LogonUI code exists?
- **ANSWER:** yes for the logic (this directory, `go test ./...` on Linux). The LogonUI proof (AC1 lab output) is NOT
  done here: it needs a Windows 10/11 client VM and the Windows toolchain. See the spec section 9.

Reference implementation of the rules, in Go, because that is what the factory host can run. The shipping DLL is
native (spec section 3) and must re-implement these rules; the tests here become its conformance vectors.
Own module, stdlib only; nothing here is imported by product code.

- `pin/` SPKI-pin TLS verification (no system roots, TLS 1.3, pin-set with backup).
- `logon/` the never-block decision: every SSPR failure maps to "show message, leave system tiles alone".
- `importscan/` PE import scanner that fails on web-rendering and shell-dialog DLLs (the TM-F-CREDPROV import scan).
