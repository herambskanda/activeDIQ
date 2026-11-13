---
title: "PSO delta directions (SYS-01) and replication error wording (SYS-03, E-S3)"
date: 2026-11-13
updated: 2026-11-13
status: draft
owner: heramb
author: ad-expert
ticket: T-1881
consumers: "reports-2-second-slice-screens.md (Screen B, Screen C); spec reports-2-second-slice.md §7.1, §7.3.7"
verification: "documentation only. Not verified on Samba or Windows. No lab run."
---

# PSO delta directions and replication error wording (T-1881)

**Conclusion first.** Microsoft publishes **no "stricter/weaker" table** for any account-policy field. Every direction
below is *our reading* of Microsoft's definition and security guidance, so each row says which. Where Microsoft's text
does not support a direction, the field ships as **"differs"**: the word, the two values, **no glyph, no colour**.
A direction we mark "Confirmed" means a Microsoft page states the monotonic effect. It does not mean Microsoft calls it "stricter".

## 1. SYS-01 direction table

"Compared" = PSO value vs. domain-head value, same field. All ten PSO attributes are `mustHave`, so a PSO always
carries a value for every field and settings from several PSOs are never merged
([PSO review, Appendix A](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754544(v=ws.10))).
The effective-value mapping (PSO attribute vs. domain attribute) is in
[MS-SAMR 3.1.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6da47028-e678-475e-b015-a5a15ee98212).

| Field (PSO attr / domain attr) | Stricter | Weaker | Status | Source and note |
| --- | --- | --- | --- | --- |
| Min length (`msDS-MinimumPasswordLength` / `minPwdLength`) | longer | shorter | **Confirmed (by definition)** | "minimum number of characters allowed in a password" [MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6da47028-e678-475e-b015-a5a15ee98212) |
| History (`msDS-PasswordHistoryLength` / `pwdHistoryLength`) | longer | shorter | **Confirmed (by definition)** | Same page; "prevents the easy reuse of old passwords" [min age page](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age) |
| Complexity (`msDS-PasswordComplexityEnabled` / `pwdProperties` bit 0x1) | on | off | **Confirmed (by definition)** | [MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6da47028-e678-475e-b015-a5a15ee98212) |
| Max age (`msDS-MaximumPasswordAge` / `maxPwdAge`) | shorter non-zero | longer; **0 / never = weakest** | **Confirmed** | "The longer a password exists, the higher the likelihood that it will be compromised"; 0 means never expires [max age](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age). **Caveat:** the same page says Microsoft's baseline omits expiry as "less effective than modern mitigations". "Stricter" here means "more frequent forced change", not "better". |
| Lock-out threshold (`msDS-LockoutThreshold` / `lockoutThreshold`) | lower non-zero | higher; **0 = never locks = weakest** | **Confirmed** | 0 "ensures that accounts won't be locked… doesn't prevent a brute force attack" [threshold](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold). Fewer failures before lock-out resists brute force sooner, but raises DoS exposure on that page: stricter is not better. |
| Lock-out duration (`msDS-LockoutDuration` / `lockoutDuration`) | longer; **0 = until an administrator unlocks = strictest** | shorter | **Confirmed** | "0 specifies that the account will be locked out until an administrator explicitly unlocks it"; non-zero "automated attempts to guess account passwords are delayed for this interval" [duration](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration). The design doc's assumption is right, and the 0 case is the inverse of max age and threshold (0 is strictest here). |
| Min age (`msDS-MinimumPasswordAge` / `minPwdAge`) | **only 0 vs. non-zero**: non-zero is stricter | 0 = immediate change allowed | **Partly confirmed** | Microsoft says 0 "isn't recommended" because with history it lets a user cycle back to the old password [min age](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age). Between two non-zero values Microsoft gives no direction (it recommends 1 day). **Two non-zero values: "differs".** The design's "longer min age is stricter" is therefore **not confirmed** beyond the 0 case. |
| Observation window (`msDS-LockoutObservationWindow` / `lockoutObservationWindow`) | — | — | **UNCONFIRMED: "differs"** | Defined as the period in which bad attempts are counted before the counter resets ([MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6da47028-e678-475e-b015-a5a15ee98212)). Microsoft's only guidance frames a *longer* value as a usability and DoS cost ("users lock themselves out for an inconveniently long period"; [reset counter](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after)), never as stricter or weaker. A longer window does make lock-out easier to reach, so "longer = stricter" is a defensible inference but it is **ours, not Microsoft's**. Design's assumption is **not confirmed**; ship "differs". |
| Reversible encryption (`msDS-PasswordReversibleEncryptionEnabled` / `pwdProperties` 0x10) | off | on | **Confirmed in direction, with an effective-value trap** | On = cleartext password recoverable ([MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6da47028-e678-475e-b015-a5a15ee98212)). **Trap:** effective value is `true` if the PSO flag is true **OR** the domain `pwdProperties` has the bit. A PSO "off" against a domain "on" is still effectively on. Show PSO off vs. domain on as **"differs"** with the note "domain setting still applies", never "stricter". Per-user `userAccountControl` bits also override ("reversible password encryption required", "password not required", "password does not expire"; [PSO review](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754544(v=ws.10))). The report states direct policy values, not a per-user result. |

### Fallback rules (acceptance 2)

1. Any field not "Confirmed" in the table ships as **"differs"**: both values, the word "differs", **no ▲/▼, no colour**.
   Fields on this list today: **observation window (always)**, **min age between two non-zero values**,
   **reversible encryption when the PSO is off and the domain is on**.
2. **Inert fields.** Duration and observation window only act when the effective threshold is above 0
   ([threshold page](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold):
   0 = never locked). When either side's threshold is 0, show duration/window deltas as "differs" with the note
   "inactive while threshold is 0". Do not call them stricter.
3. **Special values go before numeric comparison.** Max age 0 (and −1, "equivalent to 0": [max age](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age)),
   threshold 0, duration 0 (= until admin unlocks), min age 0. Sort them by the table, not by the number. Use the
   reports-2a §6.4 interval codec. Duration is stored as a negative 100 ns interval; `0` and the minimum signed
   64-bit are the "special" values. The `msDS-*` attribute encoding is as in the Interval syntax
   ([msDS-LockoutDuration](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-lockoutduration));
   how a PSO stores the "until admin unlocks" value (0 vs. min int64) is **[UNVERIFIED]** `[LAB: Windows]`. The codec must treat both as the same state.
4. **Units.** Domain and PSO values have different units in the UI tools (days, minutes) from the stored interval.
   Compare in the interval, display in days or minutes.
5. **Dependencies Microsoft states** (use for a "check" note, not a direction): when threshold > 0, duration must be ≥
   observation window, and min age < max age unless max age is 0
   ([duration](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration),
   [min age](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age)).
6. **Precedence tie.** Lower `msDS-PasswordSettingsPrecedence` wins; a tie is broken by the smallest GUID compared at the
   byte level ([PSO review](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754544(v=ws.10))).
   The design's "ties flagged, never claim a winner" is correct. Linking is to users and **global security groups
   only** (other groups are ignored by the resultant-PSO calculation), so "Applies to" on a PSO linked to a
   distribution or domain-local group is *inert*: flag it, as the effective policy would not be that PSO.

### Corrections to the design (Screen B text)

- "longer min age" is stricter: **only confirmed for 0 vs. non-zero**.
- "observation window longer = stricter": **not confirmed; "differs"**.
- "lock-out duration, 'until admin unlocks' as strictest": **confirmed**.
- "max age 0 and threshold 0 count as weaker": **confirmed**.
- Add: reversible-encryption OR rule; inert duration/window when threshold is 0.
- The legend must call these "stricter against password guessing / expiry", not "better".

## 2. SYS-03 E-S3 wording: "what it means" (no remedy)

Rules for the consumer: the meaning is **Microsoft's published text, quoted**, kept visibly separate from the DC's own
error text (spec §7.3.5). The code→meaning lookup is a static table keyed by the numeric code, never by parsing the DC string.
**No "What to do" text is shipped.** No Microsoft page I read maps these codes to a remedy that I could cite per line.
Remedy wording stays out until a sourced line exists (`[UNVERIFIED]`: Microsoft's replication-troubleshooting guidance
may supply some; not read here). The Win32 error-code pages give the decimal, hex and symbol, so lines show all three.

| Code | Symbol | Meaning (Microsoft's text) | Source |
| --- | --- | --- | --- |
| 1722 (0x6BA) | `RPC_S_SERVER_UNAVAILABLE` | The RPC server is unavailable. | [Win32 1700–3999](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-) |
| 8524 (0x214C) | `ERROR_DS_DNS_LOOKUP_FAILURE` | The DSA operation is unable to proceed because of a DNS lookup failure. | [Win32 8200–8999](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--8200-8999-) |
| 8453 (0x2105) | `ERROR_DS_DRA_ACCESS_DENIED` | Replication access was denied. | [Win32 8200–8999](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--8200-8999-) |
| 8614 (0x21A6) | `ERROR_DS_REPL_LIFETIME_EXCEEDED` | The directory service cannot replicate with this server because the time since the last replication with this server has exceeded the tombstone lifetime. | [Win32 8200–8999](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--8200-8999-) |
| 8456 (0x2108) | `ERROR_DS_DRA_SOURCE_DISABLED` | The source server is currently rejecting replication requests. | same |
| 8457 (0x2109) | `ERROR_DS_DRA_SINK_DISABLED` | The destination server is currently rejecting replication requests. | same |
| 8444 (0x20FC) | `ERROR_DS_DRA_CONNECTION_FAILED` | The server specified for this replication operation could not be contacted. | same |
| 8452 (0x2104) | `ERROR_DS_DRA_NO_REPLICA` | The naming context is in the process of being removed or is not replicated from the specified server. | same |
| 8418 (0x20E2) | `ERROR_DS_DRA_SCHEMA_MISMATCH` | The replication operation failed because of a schema mismatch between the servers involved. | same |
| 8606 (0x219E) | `ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT` | Insufficient attributes were given to create an object. This object may not exist because it may have been deleted and already garbage collected. | same |

Notes for the consumer:

- **Preview mismatch.** The Screen C preview shows its own meaning strings for 1722/8524/8453 ("The partner DC could
  not be reached over RPC.", "The destination could not resolve the partner's DNS name.", "The destination DC was
  refused by the source."). These are **paraphrases that add an interpretation** (which side, what was unreachable)
  that the Microsoft text does not state. Replace them with the quoted text above, or label them "Our reading".
  Microsoft's text for 8524 says a "DSA operation", not that the *destination* failed to resolve the *partner*.
- **Any other code**: show the number, hex, and the DC's escaped text; the meaning slot reads "No published meaning
  in our table", never a guess. 8614 is the only row tied to the at-risk indicator (spec §7.3.4); its wording says
  nothing about lingering objects, so do not add that.
- Coverage: this table is a starting set drawn from what I could confirm; it is not the full DRA error list.
- The meaning is *what Windows says the code is*, not a diagnosis of the cause. 1722 in particular is a generic RPC
  failure that many underlying problems produce; Microsoft's one-line text does not say which.

## 3. Verification status

| Item | Status |
| --- | --- |
| Direction for each "Confirmed" field | Documentation (Microsoft Learn pages above, read 2026-11-13). Not tested on a DC. |
| Reversible-encryption OR rule | Documentation (MS-SAMR 3.1.1.5). `[LAB: Windows]` to confirm. |
| PSO storage of "until admin unlocks" (0 vs. min int64) | `[UNVERIFIED]` |
| Error-code texts | Documentation (WinError.h pages). |
| Samba | Not tested. A Samba test of the delta view would not prove Windows enforcement of PSOs (Samba's PSO support is partial `[UNVERIFIED]`); a pass on Samba does not confirm these directions. |
| Remedy text | None shipped, by design. |
