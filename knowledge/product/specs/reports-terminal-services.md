---
title: "Spec: Terminal Services user reports (USR-10) and the hardened userParameters decoder"
date: 2026-11-04
updated: 2026-11-15
amended_by: T-1732 (§5, §6, §7, §8: 'collector' = connector read path, `not_confirmed`, USR-10 counts, AC-TS07 owner; author product-manager), T-1759 (§4 rules 3, 5, 6, 7 and new §4.1; §7 FR-TS03, AC-TS05, AC-TS17 to AC-TS19: blob-level vs field-level faults, gate faults, `bad_count` retired, Counts; author product-manager), T-1760 (§4.1 and AC-TS17 evidence only: cites the new safe-primitives §5.7 records TSP-38 to TSP-43 and TSP-32/33; no rule changed; author solution-architect), T-1909 (§2 traps 2, 3, 6, §3 units/text/inherit, §4 rules 3, 5, 7, 9 and §4.1, §5 read right, §6 V1/V2 settled on Windows Server 2025 build 26100; findings in domain/userparameters-windows-findings.md; author solution-architect)
status: draft
owner: heramb
author: ad-expert
ticket: T-1122
epic: E-002
milestone: M2a
parity: [ADM-084]
scope: proposed
sources_last_checked: 2026-11-04
---

# Spec: Terminal Services user reports and the userParameters decoder

> An admin who runs "Users' Terminal Services Properties" or "Users with Terminal Server Access"
> sees what Active Directory Users and Computers shows on the user's Remote Desktop Services tabs,
> row for row, and every user whose blob we cannot read is counted and named instead of guessed.

This resolves follow-up F3 of [reports-2-second-slice.md](reports-2-second-slice.md) §2, §8 and
§10. It inherits that spec's and reports-2a's library, run, scope, export and security rules.
Verification status: **documentation, plus Windows captures from T-1890** (lab DC `dc1`, Windows
Server 2025 build 26100; every captured fact is version-scoped to that build, 2019/2022 is a
follow-up). Findings and probes: [userparameters-windows-findings.md](../../development/domain/userparameters-windows-findings.md)
and `testdata/tsprops/windows/`. `[LAB: Windows]` marks what only a Windows lab can settle (here:
what the RDS session host applies at logon, which needs an RDS logon), `[UNVERIFIED]` what no
Microsoft page and no capture states. ManageEngine (ME) meanings are from
[ME's user-report help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-user-reports.html)
(read 2026-11-04), which names both reports and gives no columns.

## 1. Decision: userParameters, read-only, minimal; not msTS*

**Decision D-TS1: decode `userParameters` with a hardened, read-only, fuzzed decoder. Do not build
the reports on `msTS*`.**

Why `msTS*` is not enough, from the protocol spec and not from how often they are populated:
- [MS-TSTS §2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/9b65ec6b-a9c7-401f-bc4a-0f20538004a1)
  says of `msTSAllowLogon`, `msTSHomeDirectory`, `msTSHomeDrive`, `msTSInitialProgram`,
  `msTSMaxConnectionTime`, `msTSMaxDisconnectionTime`, `msTSMaxIdleTime`, `msTSProfilePath`,
  `msTSRemoteControl`, `msTSWorkDirectory` and the other `msTS*` session settings: "Not used by
  Terminal Services", naming the `Ctx*` property inside `userParameters` that is used instead.
- So an `msTS*` value can differ from what a terminal server enforces. A report on it is a number
  an admin can disprove in ADUC in thirty seconds (the ADUC tabs write the blob). Whether any tool
  keeps the two in sync is `[UNVERIFIED]` `[LAB: Windows]`; we do not rely on it.
- `msTSProperty01` is the personal-desktop multi-string for RDS pooled/personal collections
  ([MS-TSTS §2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/9b65ec6b-a9c7-401f-bc4a-0f20538004a1)),
  not session settings. The Win32 schema page calls it
  ["reserved for future use"](https://learn.microsoft.com/en-us/windows/win32/adschema/a-mstsproperty01),
  a conflict in Microsoft's own pages; it is out of this spec either way.
- "Rarely populated" (the second-slice §2 claim) stays `[UNVERIFIED]`; it is no longer the reason.

Why minimal: `userParameters` is one blob shared by several consumers
([MS-ADA3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/8710a141-a607-4b14-9d7c-f6370bff9b96)
says Terminal Services and the Callback Control Protocol both use it). We decode only the
properties §3 lists and treat the rest as opaque, counted and never stored.

## 2. What the attribute is (exact format)

Attribute: `userParameters`, OID 1.2.840.113556.1.4.138, syntax 2.5.5.12 (Unicode string),
single-valued, `rangeUpper` 32767, `searchFlags` 0, `FLAG_ATTR_IS_CRITICAL` since Windows Server
2008 ([MS-ADA3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/8710a141-a607-4b14-9d7c-f6370bff9b96)).
It is **not** in the global catalog partial set (captured on Windows Server 2025, T-1890); we read
it from the user's own domain, never the GC.

Layout ([MS-TSTS userParameters](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/15f8b01d-900d-4f89-a3fa-1681e55f383d),
[TSProperty](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/0bd1a91d-3cd6-4e97-b5fa-5cf35d90f005)):

| Part | Size | Rule |
| --- | --- | --- |
| ReservedData | 96 bytes | Not Terminal Services data. Microsoft's own correspondence says the RAS server uses it (dial-in/callback) and that the layout was "preliminary" ([cifs-protocol, 2011](https://lists.samba.org/archive/cifs-protocol/2011-June/001926.html)). **Never decoded, never stored.** Dial-in is `msNPAllowDialin` (second-slice §5.1) |
| Signature | 2 bytes | The Unicode character "P" (0x0050). Anything else: "all information inside TSPropertyCount and TSPropertyArray is considered invalid" (spec). Rows then read *Not configured*, not an error |
| TSPropertyCount | 2 bytes, uint16 | Number of TSProperty entries |
| TSProperty | NameLength u16, ValueLength u16, Type u16 (0x01 only), PropName, PropValue | PropName is UTF-16 of NameLength bytes. **PropValue is hex-ASCII**: each source byte becomes two ASCII hex digits, so the stored length is twice the decoded length ([encoding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/27cd734a-b780-41e6-b9d5-b6c9fba6c16a)) |

Properties are valid only if one named `CtxCfgPresent` has the value 0xB00B1E55; otherwise "Terminal
Services ignore the remaining contents". Captured (T-1909): Windows' readers also ignore the whole
blob when **`CtxCfgFlags1` is absent**, so a blob without it carries no settings (§4 rule 5), and
when `ReservedData` is all zero (see KD-1 in §4). `ReservedData` written by Windows is the UTF-16
text `CtxCfgPresent` padded with spaces to 96 bytes; dial-in callback settings do not change it.

**Traps an AD admin and an engineer both meet:**
1. **The spec says the blob is not UTF-8/UTF-16, yet the schema says Unicode string.** Microsoft
   staff called the schema syntax possibly wrong ([cifs-protocol](https://lists.samba.org/archive/cifs-protocol/2011-June/001926.html)).
   Over LDAP a Windows DC returns the UTF-16 code units converted to UTF-8; the "P" signature is
   the two bytes 0x50 0x00, which is UTF-16LE. The decoder therefore takes the LDAP octets as UTF-8,
   converts back to UTF-16LE to recover bytes, and **treats any code-unit sequence that is not valid
   UTF-8 or contains a lone surrogate as `unreadable`** (it cannot be mapped back to bytes
   losslessly). All 18 Windows captures decode strictly, including surrogate pairs (TSP-W14);
   how often real third-party blobs contain such units remains unknown.
2. **Text fields are two properties, an ANSI one and a `W` twin (T-1909, captured).** Each text
   field is written as an ANSI property (`CtxWFHomeDir`, single-byte characters, one terminating
   NUL) and a wide twin (`CtxWFHomeDirW`, UTF-16LE, terminating NUL); the same holds for
   `CtxInitialProgram`, `CtxWorkDirectory`, `CtxWFProfilePath` and `CtxWFHomeDirDrive`. Both values
   are hex-ASCII. When the text cannot be written in the ANSI code page (CJK, emoji) **only the `W`
   twin is written**. u32 values are **little-endian** (`CtxCfgPresent` is stored as `551e0bb0`).
   What Windows' own readers do: with both twins present and different, WTS and ADSI return the
   **ANSI** value; a `W`-only ASCII value reads back **empty**; a `W`-only non-ANSI value reads back
   as a lossy `?` string. Neither reader returns the true Unicode value, and which twin the RDS
   session host applies at logon is `[LAB: Windows]` (needs an RDS logon). **Decision D-TS2 (the
   decoder's rule, §3 "Text twins"):** an ANSI twin is accepted only when it is printable ASCII,
   because the ANSI code page is a property of the writing machine that a pure decoder cannot know;
   a `W` twin is accepted when it is strict UTF-16; the two must agree, and a disagreement is
   `unreadable(bad_encoding)`, never a pick, because Windows' readers and the session host are not
   known to agree.
3. **The one Microsoft table has a hole**: the 0x10000000 row of `CtxCfgFlags1` has no constant name.
   It behaves as `F1MSK_INHERITINITIALPROGRAM` in Windows' readers (captured, §3 "Inherit flags"),
   so we use that name; the name itself is ours, not Microsoft's.
4. **Duplicates, order, unknown names**: not defined by Microsoft. Captured: Windows' readers take
   the **first** occurrence of a repeated property, but an ADSI write onto a duplicated field removes
   the first occurrence and appends the new one, so the old second duplicate is then the one read.
   The RDS session host's choice was not observable. Policy in §4 (still `unreadable(duplicate)`).
   Property order and hex case do not matter to Windows.
5. **Machine policy overrides.** MS-TSTS: "Machine properties MAY override user properties". RDS
   Group Policy session limits beat the per-user value. Every report header says so.
6. **Samba gives a false pass.** Samba stores the attribute but does no Windows-side writing of it
   (no RDS tools), so Samba fixtures must be injected with LDIF; a Samba run that returns clean
   values proves nothing about Windows blobs, and Samba may return bytes that are not valid
   UTF-8, which Windows never would. Windows-captured fixtures are mandatory (§6) and now exist
   (`testdata/tsprops/windows/`).
7. **`userParameters` is not in the global catalog** (captured: `isMemberOfPartialAttributeSet`
   unset, a GC search returned the user without it). Read it from the user's own domain.

## 3. The fields we decode (closed list)

All other properties, `ReservedData`, `CtxCallbackNumber` (personal data, X11), `CtxCallBack`,
`CtxNWLogonServer`, `CtxKeyboardLayout`, `CtxMinEncryptionLevel` are **not decoded or stored**.

| Report column | Property / bit | Decode | Meaning to the admin |
| --- | --- | --- | --- |
| Logon allowed | `CtxCfgFlags1` bit `F1MSK_LOGONDISABLED` 0x00010000 | bit clear → Allowed, set → Denied | ADUC "Allow logon to terminal server" is the inverse of this bit (captured: ADSI `AllowLogon=0` stores 0x9021F000, TSP-W02). Absent blob/property → *Not configured* (ADUC shows allowed) |
| Remote control | `CtxShadow` u32 0–4 | 0 Disabled; 1 Input, notify; 2 Input, no notify; 3 View, notify; 4 View, no notify; else `unreadable` | ADUC "Remote control" tab, enabled/level/ask permission (mapping to the five values) |
| Inherit flags | `CtxCfgFlags1`: `INHERITSHADOW` 0x02000000, `INHERITMAXSESSIONTIME` 0x01000000, `INHERITMAXDISCONNECTIONTIME` 0x00800000, `INHERITMAXIDLETIME` 0x00400000, `INHERITINITIALPROGRAM` 0x10000000 | bit set → the column shows "Client/server setting"; the stored value is not shown. **Start program: the effective inherit flag is the bit set and no `CtxInitialProgram`/`CtxInitialProgramW` property present** (see "Inherit flags" below) | Whether the session host honours the other four bits is `[LAB: Windows]` (needs an RDS logon) |
| End a disconnected session / reconnect | `F1MSK_RESETBROKEN` 0x00040000, `F1MSK_RECONNECTSAME` 0x00020000 | booleans | ADUC Sessions tab |
| Session limits | `CtxMaxConnectionTime`, `CtxMaxDisconnectionTime`, `CtxMaxIdleTime` u32 little-endian, **milliseconds** (captured: 90 min is 5,400,000) | the value as a `Millis` u32, any value 0 to 4,294,967,295 (no upper bound below the u32 range; ≈ 49.7 days). 0 → "No limit" (Microsoft: a zero timeout disables the timer, [WTS_CONFIG_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_config_class); absent and stored-0 read identically). The report shows minutes, and seconds when the value is not a whole minute | ADUC Sessions tab. Run-time enforcement was not observed (no RDS session) |
| Start program, working directory | `CtxInitialProgram`/`W`, `CtxWorkDirectory`/`W` | bounded text from the ANSI/`W` pair (below, §4 rule 9) | ADUC Environment tab |
| Home folder, drive, profile path | `CtxWFHomeDir`/`W`, `CtxWFHomeDirDrive`/`W`, `CtxWFProfilePath`/`W` | bounded text from the ANSI/`W` pair; drive is `^[A-Z]:$` | ADUC RDS Profile tab. **Not** `homeDirectory`/`profilePath` (AD attributes for the normal profile); the two are shown in separate columns, never merged |
| Client drive/printer mapping | `F1MSK_AUTOCLIENTDRIVES`, `AUTOCLIENTLPTS`, `FORCECLIENTLPTDEF`, `DISABLECLIP`… | **Out in v1** (default-off column group, F-TS2) | — |

**Inherit flags (captured, T-1909).** `0x10000000` is `INHERITINITIALPROGRAM`: ADSI clears it when a
start program is set, and a raw blob with the bit set **and** a `CtxInitialProgram` stored reads as
`fInheritInitialProgram` = 0 in WTS. So the decoder outputs `inherit_initial_program` = bit set **and
neither `CtxInitialProgram` nor `CtxInitialProgramW` is present** (presence of the name, whatever its
text status). The other four inherit bits are never set or cleared by ADSI, and Windows' readers
return the stored value whether the bit is set or not; the decoder reports each bit as stored, and
what the session host does with them is `[LAB: Windows]`. An empty stored program is untested
`[UNVERIFIED]`. ADSI also writes unnamed constant bits (`0x80000000`, `0x00200000`, `0x0000F000`);
they are ignored and not counted.

**Text twins (decision D-TS2).** For each text field `X` the decoder looks at the ANSI property `X` and
the twin `XW` (`CtxWFHomeDirDrive` pairs with `CtxWFHomeDirDriveW`). Both names are known names, so
neither counts as unknown. Each value is unhexed, then exactly one terminating NUL is dropped
(ANSI: 1 byte; `W`: 2 bytes; a missing terminator or an extra NUL is `bad_encoding`).
- **ANSI** bytes must all be printable ASCII (0x20 to 0x7E); any other byte is `bad_encoding`,
  because the code page is the writing machine's and the decoder has no OS access. A genuine
  non-ASCII ANSI path therefore reads `unreadable(bad_encoding)` until a design decision adds a
  code-page input (follow-up, not v1).
- **`W`** is strict UTF-16LE (a lone surrogate or an odd byte count is `bad_encoding`).
- **ANSI only** → the ASCII text. **`W` only** → the text, **only if it holds a non-ASCII code point**;
  a `W`-only ASCII value is `bad_encoding` (a writer never produces it, and Windows' readers show it
  as empty). **Both present** → the texts must be equal, else `unreadable(bad_encoding)`: Windows'
  readers return the ANSI one, but the session host's choice is unknown, so the report picks neither.
  **Neither** → `not_configured`. An empty text (a lone NUL) is `not_configured`.
- A duplicate of either twin is `unreadable(duplicate)` for the field (§4 rule 7).
- A `W`-only value is the true Unicode text, and so differs from what ADUC and the WTS readers
  show (a lossy `?` string): V4 notes this per fixture (TSP-W13, TSP-W14).

## 4. Parser safety (the contract the build ticket implements)

Package: one decoder in the connector codec layer (`attr/tsprops`, beside `attr/flags` and
`filetime`; solution-architect places it, as for T-1124's replication decoder in
[connector-contract §5.7](../../development/architecture/connector-contract.md)).
`security-architect` reviews; the build ticket is `security-sensitive`.

1. **Read-only by construction.** No `Encode`, `Marshal` or `Set` exists for this type. A lint rule
   (fitness function) fails any call that writes `userParameters` from the product. **No
   round-trip**: the decoder never re-encodes to validate (re-encoding would hide the bytes we
   dropped, such as ReservedData and unknown properties, and a future writer built from it would
   destroy another application's data). A write feature, if ever wanted, is a separate spec that
   edits the raw bytes in place (read-modify-write of named properties only) and is
   `security-sensitive`.
2. **Input is untrusted.** The caller passes the raw LDAP octets; the decoder never panics and
   never allocates from a length field before checking it against the bytes that remain.
3. **Hard bounds (all checked before use):** input ≤ 65,536 bytes after the UTF-16 conversion
   (schema `rangeUpper` is 32,767 units); fewer than 98 bytes → *Not configured*; ≤ 64 properties
   parsed (extra ones counted, not parsed); `NameLength` ≤ 64 and even; `ValueLength` ≤ 2,048 and
   even (hex-ASCII); every `offset + length` is computed in 64-bit and compared to the remaining
   bytes; `Type` must be 0x01 else the property is `unreadable`; a u32 property whose value is not exactly 8
   hex digits is `out_of_range`. `TSPropertyCount` is never trusted:
   a count the remaining bytes cannot hold (count × 6, the size of one property header, is more than
   the bytes after the count) is a **blob-level** `truncated` fault (§4.1). Which faults make the
   whole blob unreadable and which only one field is §4.1; an odd `ValueLength` is a field fault
   `bad_hex` (rule 4), not a structural one.
4. **Strict hex.** PropValue digits are `[0-9A-Fa-f]` only; any other byte → the property is
   `unreadable`. Odd length → `unreadable`.
5. **Signature and gate.** Signature ≠ "P" → state *Not configured (no valid settings)*, reason
   `bad_signature`. A missing `CtxCfgPresent`, one whose value is not 0xB00B1E55, or one whose
   value cannot be decoded as a u32 (wrong `Type`, bad hex, wrong length) → the same state and
   reason: Windows ignores the settings, so we show none. A **duplicated** `CtxCfgPresent` is not
   this case: it is `Unreadable(duplicate)` for the whole blob (rule 7, §4.1). **A blob with no
   `CtxCfgFlags1` property is the same state and reason (T-1909)**: Windows' readers ignore the whole
   blob (PROBE-NOFLAGS), so showing its `CtxShadow` or session limits would show a setting that does
   not apply. A `CtxCfgFlags1` that is present but undecodable is a field fault of the flag-derived
   fields only. The reason of a
   *Not configured* blob is counted per run; it is not an "unreadable" reason and no cell reads
   "Unreadable".
6. **Per-field status, never per-row failure.** Each field is `value`, `not_configured`, or
   `unreadable(reason)`. A bad field never turns another field's value into a guess, and a row
   with any unreadable field still appears with that cell reading "Unreadable" and the reason in
   the details. Reasons are a closed enum: `too_short, bad_signature, bad_count, truncated,
   bad_type, bad_hex, bad_encoding, out_of_range, too_long, duplicate`. **`bad_count` is retired:**
   it stays in the enum so the wire number of the contract's `TsReason` never moves (connector-contract
   fitness TS5), but no decoder path produces it and no record or report may show it. A count the
   bytes cannot hold is `truncated` (rule 3), because it and a property that runs past the end are
   the same observable fault: the array ends before the header says it does. A blob-level fault
   (§4.1) is shown as every field `unreadable` with the blob reason; a field-level fault only on its
   own field.
7. **Duplicates and unknowns.** The same decoded name twice → both ignored and the field
   `unreadable(duplicate)`. Windows' readers take the first occurrence and the first `CtxCfgPresent`
   (captured), but an ADSI write leaves such blobs inconsistent and the RDS session host's rule is not
   observable, so a report must not pick one. An ANSI property and its `W` twin are different names
   (§3 "Text twins"), not duplicates of each other. Duplicates are found **before any field is decoded**, so the answer does not depend on
   whether a text field's encoding is settled yet (contract T7). For `CtxCfgPresent` itself the
   duplicate makes the whole blob `Unreadable(duplicate)`, since nothing can be trusted that the
   gate does not vouch for and picking one of the two values would be a guess. Unknown names are
   skipped (bounded, counted, never stored); a field-level fault in a property whose name is not
   in §3 touches no field.
8. **Typed output.** `u32` values are range-checked per §3; booleans come from named bits only; no
   `map[string]string` or raw `bytes` leaves the decoder.
9. **Text hygiene.** Decoded text is valid Unicode, ≤ 520 code points (path limit with margin), no
   C0/C1 control characters or NUL except one terminating NUL, which is dropped; otherwise
   `unreadable(bad_encoding)`. Text is untrusted display data: every output encoder escapes it
   (FF-SP4, TM-X3), including the CSV formula-prefix rule of the export code. Paths are **never
   dereferenced, resolved or tested for existence**. Text comes from the ANSI/`W` pair rule of §3.
10. **Deterministic and cheap.** Same input, same output; work is linear in the input; a 64 KiB
    input decodes in well under 10 ms (build ticket measures; budget is a test).
11. **Nothing secret.** The decoder logs no input bytes. Log lines carry the object GUID, the
    reason enum and the counts only.

**KD-1 (known divergence, T-1909).** Windows' readers also ignore a blob whose `ReservedData` is all
zero, or zero with one non-zero first or last byte or unit; all-space and 1 to 96-byte `ReservedData`
are honoured. The rule behind the boundary is unknown, and `ReservedData` is never decoded (rule 1).
v1 does **not** emulate it: such a blob decodes as `Configured` although Windows ignores it (TSP-W18).
Follow-up ticket: more probes, then a decision. Until then V4 flags such fixtures.

### 4.1 Fault classes, evaluation order and Counts

**Blob-level (structural).** The array cannot be walked, or a property cannot be matched to a field.
The whole blob is `Unreadable` with the reason; every field reads `unreadable(<reason>)`:

| Fault | Reason | Records |
| --- | --- | --- |
| input over 65,536 bytes after conversion | `too_long` | TSP-30, TSP-31 |
| not valid UTF-8, a lone surrogate (also inside a property name) | `bad_encoding` | TSP-32, TSP-33 |
| `TSPropertyCount` × 6 more than the bytes after the count; a header, name or value that runs past the end | `truncated` | TSP-13, TSP-15, TSP-16, TSP-39 (at the bound: TSP-38) |
| `NameLength` over 64 | `too_long` | TSP-17 |
| `NameLength` odd | `bad_encoding` | TSP-18 |
| a duplicated `CtxCfgPresent` | `duplicate` | TSP-26 |

**Not configured (gate).** The blob is walkable but carries no valid settings; every field reads
`not_configured`, no field is `unreadable`: fewer than 98 bytes (`too_short`, TSP-06, TSP-14);
signature ≠ "P" (`bad_signature`, TSP-10, TSP-12, TSP-29); `CtxCfgPresent` or `CtxCfgFlags1` missing, `CtxCfgPresent` wrong or
undecodable (`bad_signature`, TSP-07, TSP-11, TSP-44; undecodable: wrong `Type` TSP-40, odd hex TSP-41,
wrong length TSP-42).

**Field-level.** The name was read and its bytes are present, so only that field is affected and the
rest keep their values: `bad_type`, `bad_hex` (non-hex digit, or an odd `ValueLength`),
`out_of_range` (a `CtxShadow` over 4, or a u32 that is not 8 digits), `ValueLength` over 2,048 (`too_long`), text hygiene and a twin that is non-ASCII ANSI, `W`-only ASCII or disagrees with its pair (`bad_encoding`), and `duplicate`
of any name other than `CtxCfgPresent`. Records TSP-19 to TSP-25, TSP-27, TSP-34, TSP-35, TSP-45 to TSP-47. The
principle: fail closed where the field is unknown, fail narrow where it is known (rule 6).

**Order, so one input has one answer; the first fault found wins.**
(1) Convert LDAP octets to UTF-16LE bytes left to right: `bad_encoding` or `too_long` as met.
(2) Fewer than 98 bytes → `too_short`. (3) Signature. (4) The count check of rule 3. (5) Walk at
most 64 properties: header present, `NameLength` limits, then name and value present (`truncated`).
(6) Find duplicates among the walked names. (7) The gate: duplicated → `Unreadable(duplicate)`;
missing, wrong or undecodable `CtxCfgPresent`, or a missing `CtxCfgFlags1` → *Not configured*. (8) Decode each field. A `ValueLength` over 2,048
is judged in (8), after presence in (5), so a long value that is also cut short is `truncated`.
Bytes after the last counted property are never read, and are not an error (TSP-43).

**Counts** (`Counts` of connector-contract §5.9.1; all three are decoder outputs and never alter a field):
- `unknown_properties`: walked properties whose name is not in §3 and is not `CtxCfgPresent`, one per
  occurrence. Excluded names such as `CtxCallbackNumber` are unknown. Their values are never kept.
- `skipped_properties`: `TSPropertyCount` − 64 when the count exceeds 64, else 0. It is the number
  the header **claims**; entries past the 64th are not read, so they are not verified, beyond the
  rule 3 bound on the count.
- `duplicates`: the number of **distinct** names seen more than once among the walked properties
  (three `CtxShadow` entries is 1). It includes `CtxCfgPresent` and unknown names.
- They are set when the walk of step (5) finished, whatever the state afterwards (a duplicated gate
  gives `duplicates` 1, TSP-26), and are all 0 when it did not (a bad signature, `too_short`, a
  structural fault): a count from half a walk would depend on where the fault was.

**Fuzzing (FF-TS1, fitness function in CI):** Go native fuzz target `FuzzUserParameters`, seeded with
(a) the Windows-captured fixtures of §6 (TSP-W01 to TSP-W18), (b) hand-built hostile blobs: bad signature, count
65,535 with no data, name/value length beyond the end, odd hex, non-hex bytes, a duplicate
`CtxCfgPresent`, a thousand duplicate properties, 64 KiB of one byte, lone surrogates, NULs
inside text, an RAS-only blob with a zeroed tail. Properties asserted for every input: no panic; no
allocation above 256 KiB per call; run time under the budget; every `value` field is within its
§3 range; decode is deterministic; output never contains bytes from ReservedData (search for a
marker written there); and **a differential test** against a second, independent, deliberately
naive reference parser in the test code agrees with the decoder on every blob the reference
accepts. CI runs the seed corpus on every change and 60 s of fuzzing per night.
Minimum acceptance: 1 M executions without a finding before the build ticket may close.

## 5. The reports (USR-10, taking the reserved ID)

Dataset **D16**: `inventory.users` gains the closed column set of §3 plus `ts_state`
(`configured | not_configured | unreadable | not_confirmed`), `ts_unreadable_reason` (the §4
decoder reasons, set only when `ts_state` is `unreadable` or a field is unreadable) and
`ts_not_confirmed_reason` (set only when `ts_state` is `not_confirmed`, see below). The raw blob
is **not stored**; the decoder runs in the **connector read path** (`internal/connector/read`, on
the connector side of the contract, so a compromised server never receives the blob), and only
typed columns are persisted (D8). This is the same place as the wire-value builder of
[connector-contract §5.9](../../development/architecture/connector-contract.md); the spec
previously said "the collector", a term the architecture does not define. Read per
user from the home domain with a normal user read; no extra right is expected by default. The property
set (attributeSecurityGuid 4c164200-20c0-11d0-a768-00aa006e0529, User-Account-Restrictions) is
readable by an ordinary authenticated user **through BUILTIN\\Pre-Windows 2000 Compatible Access**, not
through a direct Authenticated Users ACE (captured, T-1890: the user class default SD gives `RP` on
the set to RAS and IAS Servers, the domain root gives it to Pre-Windows 2000 Compatible Access, and
Authenticated Users is a member of that group on the lab domain). A forest that removed that
membership (a common hardening step) denies the read for a plain user; for the connection identity
this is the `read_denied` / `readability_unknown` case below, which the rights check
(connector-contract §5.9.4) must model from the group path, not from an Authenticated Users ACE. Re-decode on every sync of
the user, since the 2a sync set uses `uSNChanged`/DirSync and the blob changes the same way as any
attribute.

**Absent is not the same as not configured.** Active Directory omits an attribute the reader
cannot see exactly as it omits one that is not set. So an absent blob is *Not configured* **only
when the connector has proved the connection identity can read it**; otherwise the state is
`not_confirmed`, the D15 "Not confirmed" pattern (§5.9.4 of the contract). A present blob proves
readability. `ts_not_confirmed_reason` is one of:

| Reason | Meaning | What the admin can do |
| --- | --- | --- |
| `read_denied` | The connection identity is denied read on `userParameters` for this user (per-object or inherited deny) | Grant read to the connection identity, or accept the count |
| `readability_unknown` | Readability could not be proved: no clean rights check this epoch, user in another domain, base read served by an RODC, an ACE form the access check cannot model | Re-run the connection's rights check; the row corrects on the next sync |
| `readability_not_evaluated` | Bulk search cannot prove readability; the sync resolves each such user with a per-user read. A row still carrying this reason means that read has not yet succeeded | None; it clears on the next sync |
| `secret_attribute` | The forest marks `userParameters` confidential or RODC-filtered, so it is never requested | Accept the count; the reports state it |

`not_confirmed` is never shown as *Not configured*, never as Basis *Default*, never as an error
row, and never silently dropped.

### USR-10a Users' Terminal Services Properties (ME name; 1 ME name)

Definition: every user in scope, with the §3 columns. Default columns: Name, Logon name, Domain,
OU path, Logon allowed, Remote control, Start program, Home folder (with drive), Profile path, Max
session / disconnected / idle (each with "Client/server setting" where inheriting), Status. A
column group "Session behaviour" (reconnect, end-disconnected) is off by default. Filters: Logon
allowed (any/allowed/denied/not configured/not confirmed), State (configured/not configured/unreadable/not
confirmed), OU, Status. A user in state *Not confirmed* shows "Not confirmed" in every §3 cell and
the reason in the State cell's detail; the cells are never blank and never read "Not configured".
A user in state *Unreadable* shows the cell-level "Unreadable" and reason of §4 rule 6.

### USR-10b Users with Terminal Server Access (ME name; 1 ME name)

ME's definition: users for whom "allow logon to terminal server" is enabled `[ME-HELP]`; ME's
treatment of users with no stored settings is `[UNVERIFIED]`.
Ours: users whose account-level setting does not deny logon. Rows carry **Basis**: *Explicit* (a
valid blob with the bit clear) or *Default* (no stored settings; ADUC shows the box ticked). A
switch "Only explicitly allowed" is off by default and a count shows each basis. Header counts:
Denied, Not readable, Not configured. **Not readable** is the sum of users in state *Unreadable*
and users in state *Not confirmed*, shown with the two parts and, for *Not confirmed*, the count
by reason; each part links to USR-10a filtered to that state. A *Not confirmed* or *Unreadable*
user is **not listed** in the 10b rows (we do not know their setting, so they have neither basis)
and is **never** given Basis *Default*; only a user whose blob is proved absent is *Default*.
Header text, always shown: "Account setting only. Whether a
user can sign in to a particular server also depends on Remote Desktop Users membership, the
'Allow log on through Remote Desktop Services' user right and Group Policy, which are not read
here." Default columns: Name, Logon name, Domain, OU path, Basis, Status.

Both USR-10a and USR-10b, and their exports, carry the *Not confirmed* count and reasons in the
header so an exported file cannot be read as complete when it is not.

Neither report is a hit-list for action (no write controls, FR-13 of reports-2a). Disabled accounts
appear with their Status, never filtered silently.

## 6. Verification plan

| Id | What | Where |
| --- | --- | --- |
| V1 | **Done on Windows Server 2025 build 26100 (T-1890, via ADSI `IADsTSUserEx`; no ADUC GUI session): TSP-W01 to TSP-W18.** Open: re-capture on 2019/2022 and an ADUC-GUI pass. Original scope: capture ≥ 12 real blobs on Windows Server 2019/2022 DCs written by ADUC (allow/deny, each remote-control level, inherit on/off, each text field set, UNC and local home, long paths, non-ASCII path characters, a user also configured for dial-in callback, a user created by a third-party tool) | `[LAB: Windows]`, follow-up F-TS1 (devops-engineer, Windows lab) |
| V2 | Settle each `[UNVERIFIED]`: **settled on Server 2025 (T-1909): text encoding (ANSI + `W` twins), u32 byte order and milliseconds, 0 = no limit, bit 0x10000000 and its precedence, readers' duplicate choice, GC membership, default read mechanism.** Still `[LAB: Windows]` (RDS logon): which twin and which inherit bits the session host applies, run-time enforcement of limits | same |
| V3 | Samba: inject the fixtures as LDIF; assert the decoder on the Samba-returned octets. **A pass here is not proof for Windows** (§2 trap 6) | Samba lab |
| V4 | Compare each report row against ADUC's tabs for the same user for all fixtures (fixture users `tspw01` to `tspw18` stay on dc1 in `OU=tspfix`; expect the documented differences: `W`-only text, TSP-W13 and W14, and KD-1, TSP-W18) | `qa-verifier`, Windows |
| V5 | For a user with a per-object deny-read ACE and one with an OU-inherited deny on the property set, confirm the DC's own answer is "cannot read" and that the report shows *Not confirmed*, `read_denied`, never *Default* (contract CC-TS-04) | `[LAB: Windows]` |

## 7. Functional requirements and acceptance criteria

| ID | Requirement |
| --- | --- |
| FR-TS01 | USR-10 MUST decode only the §3 fields, from `userParameters`, through the single decoder of §4, and MUST NOT read or display `msTS*` attributes |
| FR-TS02 | The decoder MUST satisfy §4 rules 1–11 and the fuzz target FF-TS1 MUST run in CI; no `userParameters` write MAY exist in the product (lint) |
| FR-TS03 | A user whose blob is **proved readable and absent**, has a bad signature or lacks, or has a wrong or undecodable, `CtxCfgPresent` MUST show *Not configured*, never Allowed-by-explicit and never an error row. A user whose blob is absent and **not proved readable** MUST show *Not confirmed* (§5), never *Not configured* |
| FR-TS04 | A field that cannot be decoded MUST show "Unreadable" with the reason; the header MUST count unreadable users; no value MAY be guessed |
| FR-TS08 | A user in state `not_confirmed` MUST appear in USR-10a as *Not confirmed* with its reason, MUST be counted under "Not readable" in both headers and exports, MUST NOT appear in USR-10b rows, and MUST NOT be given Basis *Default* or counted under "Not configured" |
| FR-TS09 | The decoder MUST run in the connector read path and only typed columns MAY cross the connector contract (contract §5.9 T3); no server-side code MAY receive or decode the raw blob |
| FR-TS05 | USR-10b MUST show Basis, the account-setting-only header, and MUST NOT list a user whose bit denies logon |
| FR-TS06 | Every text value MUST be escaped on every output and never dereferenced |
| FR-TS07 | The raw blob and ReservedData MUST NOT be stored, logged, exported or returned by the API |

Acceptance (Given/When/Then; ground truth is the Windows fixture and ADUC unless stated):
- **AC-TS01** Given the 12 Windows fixtures, When USR-10a runs, Then every cell equals ADUC's tab for that user. *Evidence: V4 report* `[LAB: Windows]`.
- **AC-TS02** Given a user with the deny bit set, When USR-10b runs, Then the user is absent and the header "Denied" count includes them.
- **AC-TS03** Given a user with no `userParameters`, When USR-10b runs, Then the row has Basis "Default"; with "Only explicitly allowed" on, it is absent.
- **AC-TS04** Given a blob with signature "Q", When either report runs, Then State is *Not configured* and no field is "Unreadable".
- **AC-TS05** Given a blob with `TSPropertyCount` 65,535 and no data, When decoded, Then State is `Unreadable`, reason `truncated` (never `bad_count`), every field `unreadable(truncated)`, no panic, allocation under 256 KiB. *Evidence: unit test, record TSP-13.*
- **AC-TS06** Given a blob carrying `CtxWFProfilePath` of `=HYPERLINK(…)`, When exported to CSV and rendered in the grid, Then it is neutralised on both outputs.
- **AC-TS07** Given a blob with a sentinel in ReservedData (and an unknown property carrying a sentinel value), When the full pipeline runs (sync, USR-10a and USR-10b, CSV/XLSX/PDF/HTML exports, API), Then the sentinel, in UTF-8, UTF-16LE and hex form, appears in no table dump, log line, export or API response, and the test fails when a deliberate leak is introduced. *Evidence: the lab end-to-end test **TS8** of connector-contract "Fitness functions added in v1.5" (ticket **T-1733**), owner **`test-engineer`**; the connector-level cases are TS6 and are not this criterion.*
- **AC-TS08** Given the fuzz target, When CI runs, Then the seed corpus passes and the nightly job reports executions and zero findings.
- **AC-TS09** Given a user with `CtxMaxIdleTime` set and its inherit bit set, When USR-10a runs, Then the cell reads "Client/server setting" `[LAB: Windows]`. Given `CtxInitialProgram` stored and the inherit-program bit set, Then the start-program cell shows the program (TSP-48).
- **AC-TS10** Given a repo search, When the lint runs, Then no code path writes `userParameters`.
- **AC-TS11** Given two properties named `CtxWFHomeDir`, When decoded, Then the field is `unreadable(duplicate)` and the other fields still show values. *Evidence: unit test, record TSP-25.*
- **AC-TS12** Given a user whose `userParameters` is absent and the connection identity is denied read on it (a per-object deny and, separately, an inherited deny), When the sync, USR-10a and USR-10b run, Then USR-10a shows State *Not confirmed* with reason `read_denied`, USR-10b does not list the user and its "Not readable" count includes them, and no report row shows Basis *Default* or *Not configured* for that user. *Evidence: V5 on Windows; Samba rows are not evidence of the access check* `[LAB: Windows]`.
- **AC-TS13** Given a user with no `userParameters` whose readability is proved, When USR-10b runs, Then the row has Basis *Default* (as AC-TS03); and Given the same user when readability cannot be proved (no clean rights check this epoch), Then the user is *Not confirmed*, `readability_unknown`, and absent from the 10b rows.
- **AC-TS14** Given a sync in which bulk search returned a user with no blob, When the sync completes, Then each such user has been resolved by a per-user read to *Not configured* or *Not confirmed* with a reason other than `readability_not_evaluated`; a user whose per-user read failed stays `readability_not_evaluated` and is counted under "Not readable".
- **AC-TS15** Given a forest where `userParameters` is confidential or RODC-filtered, When either report runs, Then every user is *Not confirmed*, `secret_attribute`, the header says so once, and no request names the attribute.
- **AC-TS16** Given a mix of Denied, Not configured, Unreadable and Not confirmed users, When USR-10b is exported, Then the file's header carries the same four counts as the screen and "Not readable" equals Unreadable plus Not confirmed.

- **AC-TS17** Given a blob with a structural fault (a name or value running past the end, `NameLength` 66, `NameLength` 17, invalid UTF-8, input one unit over the cap), When decoded, Then State is `Unreadable` with the §4.1 reason, every field is `unreadable` with it, and all three Counts are 0. Given instead a field fault (`CtxShadow` of `Type` 2, `CtxMaxIdleTime` of 6 hex digits, a 2,050-digit `CtxInitialProgram`, odd hex), Then State is `Configured`, only that field is `unreadable` with its reason, and the others keep their values. *Evidence: unit test, records TSP-15 to TSP-24, TSP-30, TSP-32, TSP-33.*
- **AC-TS20** Given the 18 Windows fixtures, When decoded, Then each record equals its typed expectation in `attr.tsprops` (TSP-W01 to TSP-W18), session limits are in milliseconds, text comes from the ANSI/`W` pair rule, and a `W`-only non-ANSI text is the Unicode text. Given an ANSI and a `W` twin that differ, or a `W`-only ASCII value, or a non-ASCII ANSI byte, Then that field is `unreadable(bad_encoding)` and the others keep their values. *Evidence: unit test, records TSP-W01 to TSP-W18, TSP-45 to TSP-47.*
- **AC-TS18** Given a blob whose `CtxCfgPresent` is missing, or 0xB00B1E54, or that has no `CtxCfgFlags1`, When decoded, Then State is `NotConfigured`, reason `bad_signature`, no field is `unreadable`; and Given `CtxCfgPresent` twice, Then State is `Unreadable`, reason `duplicate`, `duplicates` 1, whatever the text-field encoding is. *Evidence: unit test, records TSP-07, TSP-11, TSP-26, TSP-44.*
- **AC-TS19** Given `TSPropertyCount` 1,002 with 1,000 `CtxShadow` entries after the gate and flags, When decoded, Then `skipped_properties` is 938, `duplicates` is 1 and `unknown_properties` is 0; and Given `TSPropertyCount` 67 with 61 walked unknown names, Then `unknown_properties` is 61 and `skipped_properties` is 3. *Evidence: unit test, records TSP-27, TSP-28.*

## 8. Handoffs and follow-ups

- `product-manager`: fold into second-slice §2/§8/§10 (F3 resolved), §3 (USR-10 now specced; 2 ME names, ADM-084 count 18), and the counts; T-1112 retitle in T-1118 is now moot for USR-10 which is a separate batch.
- `test-engineer`: AC-TS07 end to end as TS8 (T-1733). `qa-verifier`: AC-TS12 to AC-TS16 on a Windows lab. `reporting-engineer`: the D16 columns, USR-10a/10b states, counts and export headers of §5.
- `solution-architect`: decoder placement is settled by connector-contract v1.5 §5.9 (T-1567); confirm the closed-AST fragments (a plain boolean/enum filter, no new fragment expected); `security-architect`: review D16, V-lint and FF-TS1.
- `directory-engineer`: build the decoder and D16 after V1/V2 fixtures exist; `devops-engineer`: capture fixtures (V1).
- New tickets to file: **F-TS1** Windows fixtures V1/V2 (blocks the build); **F-TS2** client drive/printer mapping and session-behaviour columns (P4, optional); build ticket for decoder + D16 + USR-10.
- Parity differences chosen on purpose: **P7** Users with Terminal Server Access shows Basis and says it is account-level only; ME's treatment of "no stored settings" is `[UNVERIFIED]` and is compared in T-1120 (F1).
- Glossary: *userParameters*, *TSProperty*, *Remote Desktop Services profile* (to add via the `memory` skill).

## 9. Open questions

None for the CEO. Engineering unknowns are the `[UNVERIFIED]` and `[LAB: Windows]` tags; V1/V2 closed most of them on Windows Server 2025. What remains needs an RDS logon (twin and inherit-bit use by the session host), the 2019/2022 re-capture, and KD-1's rule.
