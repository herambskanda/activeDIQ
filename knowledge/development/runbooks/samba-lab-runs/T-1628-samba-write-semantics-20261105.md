---
title: T-1628 — Samba 4.22.11 write semantics for restore, unlock and policy hints
status: draft
owner: ad-expert
ticket: T-1628
---
# T-1628 run, 2026-11-05

Target: the per-worktree Samba lab (Samba 4.22.11, forest/domain level 2008 R2, single DC), LDAP with StartTLS as
`Administrator`, test objects `t1628-*` under `OU=Managed`. The lab was `make lab-reset` afterwards (Recycle Bin back off,
password settings back to default). Full transcript: `T-1628-samba-write-semantics-20261105.log.txt`.
**Not run on Windows**: the Windows lab had no VMs; the Windows-only items stay `[UNVERIFIED Windows]` in connector-contract §8.10 and are carried by CC-WK-16, 18 and 24 (W).

| # | Question | Samba 4.22.11 result | Windows |
| --- | --- | --- | --- |
| 1 | Show-deleted OID | `1.2.840.113556.1.4.417` and show-recycled `…2064` are in `supportedControl`; a search without 417 returns no deleted object | Confirmed by [Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-show-deleted-oid) |
| 2 | Restore modify shape | `delete isDeleted` + `replace distinguishedName` with critical 417 works on a **tombstone** (Recycle Bin off); group memberships are not back | [MS-ADTS 3.1.1.5.3.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4302a2eb-55c8-426c-b310-6791c6ae8307), [restore procedure](https://learn.microsoft.com/en-us/windows/win32/ad/restoring-deleted-objects) |
| 3 | Recycle Bin on Samba | `msDS-EnabledFeature` is system-only; `enableOptionalFeature` on the rootDSE is refused to Administrator ("Insufficient rights"); only an in-process system session enabled it | n/a |
| 4 | Restore with Recycle Bin on | **Fails**: `noSuchAttribute`, `isRecycled` cannot be deleted; same with 2064, permissive-modify 1413, explicit `delete isRecycled`; `replace isDeleted FALSE` is `constraintViolation` (system-only) | Works ([MS-ADTS constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/76df255d-dc67-4c1f-adc6-1e5b60021304)) `[UNVERIFIED lab]` |
| 5 | Link retention | RB off: `member`/`memberOf` gone. RB on: deleted user keeps `memberOf`; group `member` still **shows** the mangled DN on a plain read (Windows hides it) | [MS-ADTS 3.1.1.1.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/538ec135-1465-4266-bb0a-777924f02846) |
| 6 | Unlock forms | `replace lockoutTime 0` and `delete lockoutTime <read value>` + `add lockoutTime 0` both unlock, `badPwdCount` 0, computed UAC 16 to 0; stale old value → `noSuchAttribute` (a true compare-and-set); `replace` on an unlocked account succeeds | delete-old form `[UNVERIFIED Windows]` |
| 7 | Non-zero `lockoutTime` | Accepted, sets the computed lock bit | Reported rejected `[UNVERIFIED]` |
| 8 | Policy hints `…2239` | Not in `supportedControl`; accepted and **ignored** even as critical; with history 3 and minimum age 1 day the same password was accepted again | Honoured (T-0076, WS2025) |

False-pass traps for the test-engineer: rows 2, 4, 5, 7, 8. Method notes: `ldapmodify` cannot send the 2239 control (its value did not parse); a go-ldap v3.4.13 probe sent it raw, value `30 03 02 01 01`.
