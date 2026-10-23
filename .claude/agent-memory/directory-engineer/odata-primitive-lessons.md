---
name: odata-primitive-lessons
description: P8 odata build gotchas - external test pkg, corpus value expectations, quote-doubling home, stray report dir
metadata:
  type: feedback
---

- Tests that import `graphschema` must live in `package odata_test` (graphschema imports odata: cycle otherwise).
- One corpus record has one `expect` key; when both the decoded filter and the encoded query matter use `expect.value` `{"filter","query"}`.
- Adding a primitive home needs: `corpus.Units`, `policy.UnitHomes`, the FF-SP3 quote-doubling home list in goscan.go, fuzz `requiredProps`, blueprint "directory primitives" class.
- **Why:** each was a separate failure of a gate I only found by running it.
- Never set `SAFEPRIM_REPORT_DIR` to a relative `../..` path: it wrote a stray report outside the worktree.
- Pre-existing red on main (not ours): corpus gate `dn` undeclared, `tls_test.go` InsecureSkipVerify, TestFixtureEnvIsClean (no node deps).

## T-0225 (PIM-for-Groups)
- Graph errors now carry `GraphCode` (error.code only); G11 unlicensed signal is `tier0.PIMUnlicensed{HTTPStatus,GraphCode,PlanIDs}`, zero value = fail closed until lab G11 pins it.
- No protoc locally: PIM-read requirement is attributed to the lowest enabled write family instead of a new RightsFamily enum.
- `tools/fitness/stack` TestTheRealTreeIsGreenWhenGitIsAvailable is red on main (apitls perm_*.go "unix" build tag), unrelated.
