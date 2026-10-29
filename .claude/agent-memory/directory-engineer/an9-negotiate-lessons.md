---
name: an9-negotiate-lessons
description: Traps met building the AN-9 SPNEGO core (T-0206)
metadata:
  type: reference
---

- fitness A11 forbids http.Error/WriteHeader in internal/** outside apihost: non-API routes return `apihost.NonAPIResult` and mount via `ServeNonAPI`.
- `sid.SID{}.Bytes()` is an 8-byte header, not empty; guard on length < 12 before using it as a query key.
- inventory test fixture `sid` ({1,1,...} 16 bytes) is malformed for `sid.FromBytes`; use {1,2,...} in new tests.
- Epoch (T-0429) cannot precede ticket verification for Kerberos (account unknown until the PAC SID maps); documented in negotiate.SignIn.
- `TestFixtureEnvIsClean` in tools/fitness/api fails without `make web-install` (ajv): pre-existing, not the change.
