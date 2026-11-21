---
name: dcjoin-lessons
description: T-1636 DC-log join e2e - Samba audit log levels, runner ctx gaps, disable/enable skipped, lab rig recipe
metadata:
  type: reference
---

- `smbcontrol samba debug` only reaches the parent; use `smbcontrol all debug "auth_audit:5 dsdb_audit:5 dsdb_password_audit:5"` or no `DSDB Change` line appears. Log: `/var/log/samba/log.samba`, read from a byte offset (`wc -c`, `tail -c +N`). Slow: the test takes ~200 s per PG version.
- A reset logs `replace: unicodePwd [REDACTED SECRET ATTRIBUTE]` plus `Password Change [Reset]`; the SID is the bound svc account.
- Lab rig users are created disabled (UAC 546). Enable/disable/unlock Actions have an empty Diff so SubmitDirectory skips them as no_change (T-2301); use reset password (needs `FreshStepUp` and `Secrets{0: ...}`).
- Runner Apply/Verify/Observe ctx had no tenant, and ad Apply had no DSA pin: both failed `outcome_unknown`. `client.Write` also sends no DirectoryIdentity (T-2303).
- Step audit event is the one whose Kind equals the Action's audit kind; started/completed events share the operation but carry no dc/credential_id. `dc` detail is the pinner's host, not the DSA GUID.
- `newLabRigWith(t, s, actions)` in operation_lab_test.go builds the runner rig with real Actions; the rig needed `Credentials` (it was red since T-1629).
- Review round 2: the live log.samba holds the DC's own writes (DC1$ DNS, SID -1000) and other lab users'; scope SID assertions to `DSDB Change` lines containing the target DN (lowercased), not the whole window. Background commands die at 10 min: give `timeout` up to 3600000.
- Tenant-on-ctx unit guard: dirFake.seeTenant in operation/persist_pg_test.go; DSA pin guard: accounts.wrotePins in modules/ad/ad_test.go.
