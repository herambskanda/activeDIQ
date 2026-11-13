---
title: "userParameters on Windows: captured fixtures and the settled [UNVERIFIED] list (V1/V2)"
date: 2026-11-13
updated: 2026-11-13
status: draft
owner: devops-engineer
ticket: T-1890
---

# userParameters on Windows: what the captures show

Scope ruling (director, T-1890 note 2026-11-13): captured on the lab DC `dc1`, **Windows Server 2025 Standard Evaluation, build 26100**
(forest and domain level 2025), not 2019/2022. Every finding below is **version-scoped to that build**; the 2019/2022 re-capture is a
backlog follow-up. Writers: ADSI `IADsTSUserEx` (the API ADUC binds to; no ADUC GUI session was available) for TSP-W01..W16, a plain LDAP
modify with a blob we assembled (not an independent third-party product) for TSP-W17/W18. Readers used to check each record: raw LDAP octets,
`WTSQueryUserConfig` and the ADSI properties, all run on dc1 by `lab/windows/bin/capture-tsprops`.
Data: `testdata/tsprops/windows/` (`captures.json` raw, `records.jsonl` TSP-W01..W18, `probes.jsonl` 39 probes). Spec under test:
[reports-terminal-services.md](../../product/specs/reports-terminal-services.md).

## Verdicts

| # | Spec claim (tag) | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | Text fields are UTF-16LE with a terminating NUL (§2 trap 2) | **Changed.** Windows writes each text field as **two properties**: an ANSI one (`CtxWFHomeDir`, single-byte, NUL-terminated) and a wide twin (`CtxWFHomeDirW`, UTF-16LE, NUL-terminated); same for `CtxInitialProgram`, `CtxWorkDirectory`, `CtxWFProfilePath`, `CtxWFHomeDirDrive`. When the text is not representable in the ANSI code page (CJK, emoji; TSP-W13, W14) **only the `W` twin is written**. Both are hex-ASCII, NUL-terminated. u32 values are **little-endian** (the `[UNVERIFIED]` byte-order assumption in safe-primitives §5.7 is confirmed) | TSP-W09..W14; `CtxCfgPresent` stored as `551e0bb0` |
| 1b | Which twin do Windows' readers use | **Observed, partly odd.** With both present and different, WTS and ADSI return the **ANSI** value (PROBE-ENC-DISAGREE). A `W`-only ASCII value reads back **empty** (PROBE-ENC-WIDE-ASCII, -WIDE-DRIVE); a `W`-only non-ANSI value reads back as a **lossy `?` string** (TSP-W13/W14, PROBE-ENC-WIDE-CJK). So neither reader returns the true Unicode value. Which twin the RDS session host applies at logon is **confirmed-still-unknown**: needs an RDS logon, not possible on a DC | |
| 2 | 0 = "No limit" (§3) | **Confirmed by documentation, changed in unit.** Microsoft documents that a zero timeout disables the timer ([WTS_CONFIG_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_config_class)). Absent and stored-0 read identically (PROBE-ZERO-ABSENT/-0). **The unit is milliseconds, not minutes**: 90 min is stored as `c0655200` = 5,400,000 (TSP-W08), WTS returns 900000 for 15 min (W16 has 45 min = 2,700,000). ADSI rejects 100,000 minutes (PROBE-OVERFLOW). The spec's "u32 minutes, > 525,600 → unreadable" is wrong: the u32 ceiling is ≈ 49.7 days. Run-time enforcement was not observed (no RDS session) | TSP-W08, W16, probes |
| 3 | Bit `0x10000000` = `INHERITINITIALPROGRAM` (§3) | **Confirmed, with a precedence nuance.** Setting a start program through ADSI clears the bit (default `9020f000` → `8020f000`, TSP-W11/W13/W16). Raw writes: bit clear → WTS `fInheritInitialProgram` = 0; bit set and no program → 1; **bit set but a `CtxInitialProgram` stored → 0** (PROBE-INH1A/1B). The other four inherit bits (`0x02000000`, `0x01000000`, `0x00800000`, `0x00400000`) are **never set or cleared by ADSI**, and the readers return the stored value whether the bit is set or not (PROBE-INH-*). Whether the session host honours them is **confirmed-still-unknown** (needs an RDS logon). Observed constants in every ADSI-written flags value: `0x80000000`/`0x10000000` (fresh), `0x00200000`, `0x0000F000`, names unknown | TSP-W11, W13, W16, PROBE-INH* |
| 4 | Duplicate fields: Windows' choice unknown (§4 rule 7) | **Settled for the readers, conservative choice kept.** WTS and ADSI take the **first occurrence** of a repeated property (PROBE-DUP1: 2 then 4 reads 2; DUP2: 4 then 2 reads 4; DUP5 text), and the **first `CtxCfgPresent`** (DUP3 good-then-bad honoured; DUP4 bad-then-good ignored). An ADSI write onto a duplicated field does **not** produce the written value: it removes the first occurrence and appends the new one, so the old second duplicate is still read (DUP1: write 3 on `[2,4]` leaves `[4,3]` and reads 4). Keep `Unreadable(duplicate)`: the RDS session host's rule was not observable, and ADUC itself leaves such blobs inconsistent | PROBE-DUP1..5 |
| 5 | Is `userParameters` in the global catalog (§2) | **Confirmed not.** Schema `isMemberOfPartialAttributeSet` is unset; a GC (3268) search as Administrator returned the user without the attribute | notes `SCHEMA`, `GC` |
| 6 | Default read right: property set `4c164200-…` read by authenticated users (§5) | **Changed in mechanism.** `attributeSecurityGUID` is `4c164200-20c0-11d0-a768-00aa006e0529` (User-Account-Restrictions), syntax 2.5.5.12, `rangeUpper` 32767, `searchFlags` 0, `systemFlags` 16 (matches the spec). The user class default SD gives `RP` on that set to **RAS and IAS Servers** and the domain root gives it to **BUILTIN\Pre-Windows 2000 Compatible Access**; there is **no direct Authenticated Users ACE**. A plain user with no group memberships read it (and `cn`, `sAMAccountName` as controls) because Authenticated Users is a member of that group on this domain. Removing that membership (a common hardening step) would deny the read, which is exactly the `not_confirmed`/`read_denied` case of spec §5 | notes `ACL`, `ACLU`, `PRE2K`, `USERREAD` |

## Other facts the decoder needs

- Windows-written `ReservedData` is the UTF-16 text `CtxCfgPresent` padded with spaces to 96 bytes, **not** RAS data. Configuring dial-in with a callback number (`msNPAllowDialin`, `msRADIUSCallbackNumber`) left the blob byte-for-byte equal in shape to a non-dial-in one (TSP-W15 vs W04): those settings live in their own attributes.
- **Windows' readers ignore the whole blob** when `CtxCfgFlags1` is absent (PROBE-NOFLAGS), when the first `CtxCfgPresent` is wrong (DUP4), and with all-zero `ReservedData` or zeros with a single non-zero first/last byte or unit (PROBE-RES-ZERO/-FIRSTBYTE/-LASTBYTE/-U0020ONLY/-U0201ONLY). All-space and 1..96-byte `ReservedData` are honoured. The rule behind this is **unknown**; the DC stores all of them losslessly. So a blob the spec calls valid can be one Windows ignores (TSP-W18). Property order and hex case do not matter (PROBE-ORDER-*, -UPPERHEX).
- Property `Type` is always 1; ADSI writes `CtxCfgPresent` first, `CtxCfgFlags1` second or last (order varies).
- ADSI accepted a 230-character home path and rejected 255 and longer (generic "directory property cannot be found in the cache" error); TSP-W12 holds 196 and 230 characters. Largest `ValueLength` seen: 924 hex digits (`CtxWFProfilePathW`), inside the spec's 2,048 bound.
- The LDAP octets are the UTF-8 of the UTF-16 code units, as spec trap 1 says; all 18 records decode strictly, including the surrogate pairs of TSP-W14.

## What this means for the build and docs (follow-ups filed)

1. Spec / contract / safe-primitives §5.7 must change: millisecond units and bound, the ANSI + `W` property pairs and which to decode, inherit precedence, duplicate rule note, default-read-right mechanism, `ReservedData` and missing-flags acceptance. T-1566 cannot decode text safely until that is decided.
2. A `windows_effective` flag on each record tells T-1566 and QA which blobs Windows itself ignores.
3. Re-capture on Windows Server 2019/2022 and an RDS-session check of inherit bits and the twin precedence.
4. V4 (compare each report row with the ADUC tabs) still needs a GUI session; the fixture users `tspw01..tspw18` stay on dc1 in `OU=tspfix` (disabled, no password) for it.
