---
title: "Account-state lab rows: lockout, fine-grained password policy (PSO) and expiry"
date: 2026-10-31
updated: 2026-10-31
status: review
owner: heramb
author: ad-expert
ticket: T-1016
---

# Account-state lab rows (lockout, PSO, expiry)

**What this is.** The cases that prove the report engine's derived states
([reports-2a §6.4](../../product/specs/reports-2a.md), [modules/reports.md §3.3](../architecture/modules/reports.md))
equal what a domain controller says. Each row has a setup, the inputs the engine reads (DM-16
"Report-engine inputs"), the expected report state, the **oracle** (the DC's own constructed attribute,
which an admin can also read in ADUC or `Get-ADUser`), and where it can run.

**Verification status of the whole file: documentation and Samba source only.** Nothing below was
run on Samba or Windows by this ticket. The Samba lab was not up in the authoring environment. The
"Samba" column is what Samba's source says it does
([`operational.c`](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/operational.c), read 2026-10-31), not a measurement. A row becomes
`[LAB: Samba]` or `[LAB: Windows]` only when a run log records it (convention:
`knowledge/development/runbooks/windows-lab-runs/`).

**Run column.** `S` runs on the Samba lab and the result carries over. `S*` runs on Samba but
**Samba would give a false pass or a different answer** (stated in the row). `W` needs the Windows lab
(`windows-lab.md`). `Syn` is a synthetic RP8 unit case: a live DC cannot be made to hit an exact tick,
and the engine takes `now` as an argument, so boundaries are proved with injected clocks.

## 1. The rules the rows prove

Primary sources: [msDS-User-Account-Control-Computed](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2),
[msDS-UserPasswordExpiryTimeComputed](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f9e9b7e2-c7ac-4db6-ba38-71d9696981e9),
[msDS-ResultantPSO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad735d45-ba6a-42fc-a41c-e91ced8e72d9),
[Effective policy values (MS-SAMR 3.1.1.5)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6da47028-e678-475e-b015-a5a15ee98212),
[accountExpires](https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires),
[GetMemberships](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/37846a89-a75a-4e9a-9391-d564fc1cfb80).

| # | Rule (MS-ADTS wording in brackets) | Consequence for the report |
| --- | --- | --- |
| R1 | **Locked** when no trust bit (`WORKSTATION_TRUST`, `SERVER_TRUST`, `INTERDOMAIN_TRUST`) is set, `lockoutTime` is non-zero, and either the effective duration, read as unsigned, is `< 0x8000000000000000` **or** `ST + duration ≤ lockoutTime` (signed). | Stored duration 0 and stored `MinInt64` both mean "until an admin unlocks": the first by clause (1), the second because `ST + MinInt64` is always `≤ lockoutTime`. Otherwise the lock holds while `now ≤ lockoutTime + |duration|`: **inclusive**. There is **no** `ACCOUNTDISABLE` test, so a disabled user with a live `lockoutTime` is locked. |
| R2 | **Password-expired bit (PE)** is set when none of `SMARTCARD_REQUIRED`, `DONT_EXPIRE_PASSWD`, the three trust bits is set **and** (`pwdLastSet` null, or 0, or (`maxAge ≠ 0x8000000000000000` and `ST − pwdLastSet > maxAge`)). | Strict `>`. **`pwdLastSet = 0` sets PE**, so the DC's own "password expired" bit includes "must change at next logon". The engine separates them (§6.4 rows 4 and 6) and the reconciliation is `count(PE bit) = count(must change) + count(expired)` over non-exempt users. |
| R3 | `msDS-UserPasswordExpiryTimeComputed` = `0x7FFFFFFFFFFFFFFF` for the exempt bits (smartcard, DONT_EXPIRE, trust); else `0` when `pwdLastSet` is null or 0; else `0x7FFF…` when `maxAge = 0x8000000000000000`; else `pwdLastSet + maxAge`. | Order matters and matches §6.4: exempt flags first, then must-change, then policy-never, then the date. |
| R4 | **Effective policy**: the user's `msDS-ResultantPSO` object's `msDS-MaximumPasswordAge` and `msDS-LockoutDuration` when it has one, else the domain's `maxPwdAge` and `lockoutDuration`. | The two values are *stored negative* (100 ns deltas). MS-ADTS writes the formula with the magnitude; a literal reading with the stored negative would mark every password expired. The codec takes the magnitude and treats a **positive** stored value as invalid (Unknown). |
| R5 | **`msDS-ResultantPSO`**: no value if the domain functional level is below 2008, the class is not `user`, `NORMAL_ACCOUNT` is not set, the RID is `krbtgt` (not enforced by Windows Server 2016 and earlier), or `msDS-SecondaryKrbTgtNumber` has a value (RODC krbtgt). Otherwise the PSOs in the user's own `msDS-PSOApplied` (the back-link of `msDS-PSOAppliesTo`) form the candidate set; **only when that set is empty** are the PSOs applied to the user's account groups (transitive `memberOf` **plus the `primaryGroupID` edge**, limited to the DC's domain) added. Sort by `msDS-PasswordSettingsPrecedence`, ties by `objectGUID`, smaller first; the first wins. | A direct link beats every group link whatever the precedence. A PSO on Domain Users reaches everyone through the primary-group edge though `member` never lists them. |
| R6 | **Never expires** for an account: `accountExpires` 0 or `0x7FFFFFFFFFFFFFFF`. | Expired comparison itself (`<` or `≤` `now`) is `[UNVERIFIED]`; the boundary is a `W` row. |
| R7 | `lockoutTime` is **not** reset when a lockout lapses. | A lapsed lock keeps a non-zero `lockoutTime` and a clear UF_LOCKOUT bit. |

**Open points the sources do not settle** (each has a row): (a) whether a stored domain `maxPwdAge` of
**0** means "never" (MS-ADTS names only `MinInt64`; Samba treats `≥ −1`, which includes 0, as never);
(b) which values ADAC, `Set-ADDefaultDomainPasswordPolicy`, `New-ADFineGrainedPasswordPolicy` and GPO
write for "never"; (c) the group scope and type a PSO link honours (Microsoft's guide says global
security groups, MS-ADTS's pseudocode shows no filter); (d) how equal-precedence PSOs compare by
`objectGUID` (wire bytes or GUID fields); (e) the smartcard case at functional level 2016 with
`msDS-ExpirePasswordsOnSmartCardOnlyAccounts` (Samba computes a real expiry there, MS-ADTS says
`0x7FFF…`; a Microsoft engineer points to MS-ADA2 and MS-SAMS for the attribute,
[thread](https://lists.samba.org/archive/cifs-protocol/2024-April/004287.html));
(f) the default read ACL on the Password Settings Container.

## 2. Lab policy and fixtures

- **Domain policy** of the Samba lab: max age 90 days, lockout after 5 bad passwords, duration "until an
  admin unlocks" ([ad-lab.md §2](../runbooks/ad-lab.md)). The rows that need a **finite** lock use a
  PSO with a 1-minute duration and 1-minute observation window (observation window ≤ duration), not a
  change to the domain policy, so the seed stays untouched. The two rows that must change the domain
  policy (PW-13, PW-09) end with `make lab-reset`.
- **Lockouts are made by real failed binds** (the `post-start.sh` method), never by writing
  `lockoutTime`: on Windows only the value 0 can be written by a client `[UNVERIFIED]`.
- **Password ages** use the seed's set-back clock (`faketime`, ad-lab §3). Samba accepts `pwdLastSet`
  only as 0 or −1 over LDAP, so a row cannot write an arbitrary `pwdLastSet`. On Windows an arbitrary
  value cannot be written either: use the same technique (clock) or choose rows that need only 0 or "now".
- **Oracles read live and compared to the engine's result at the same `now`**: `msDS-User-Account-Control-Computed`
  (bits `0x10` lockout, `0x800000` PE), `msDS-UserPasswordExpiryTimeComputed`, `msDS-ResultantPSO`.
  A run reads them from the same DC as the sync. Lag between sync and oracle is removed by a sync pass
  immediately before the oracle read.
- The oracle is **not** a product dependency (DM-16.I5a, RP3): it is the test's ground truth.

## 3. Lockout rows

| ID | Setup | Engine inputs | Expected report state | Oracle | Run | Trap |
| --- | --- | --- | --- | --- | --- | --- |
| LAB-LK-01 | Domain duration "until unlocked". Lock a user with 5 bad binds. Seed has 25 such users | `lockoutTime ≠ 0`, `uac` normal, domain `lockoutDuration` | Locked out, "Lockout ends: until an admin unlocks". The seed's `locked_samaccountnames` equal the report's set (25) | UF_LOCKOUT `0x10` set | S | Report must show the *stored* duration read from the DC, not 0 as "no policy" |
| LAB-LK-02 | PSO (1-minute duration and window) on user; 5 bad binds; wait 61 s; sync | `lockoutTime ≠ 0` (still), PSO duration 1 min | **Not** locked. `lockoutTime` is still non-zero in the row | UF_LOCKOUT clear; `lockoutTime` unchanged (R7) | S | A stored flag, or "non-zero `lockoutTime` = locked", fails here |
| LAB-LK-03 | Same user and PSO, domain still "until unlocked"; check at +30 s and +120 s | PSO duration beats domain | +30 s locked, +120 s not locked, policy source = PSO name | UF_LOCKOUT | S | If the engine used the domain duration it shows locked at +120 s: the admin sees "unlocked" in ADUC |
| LAB-LK-04 | Boundary: duration D, `now = lockoutTime + D − 1 tick`, `= + D`, `= + D + 1 tick` | injected | locked, **locked**, not locked (inclusive, R1) | n/a | Syn | The first spec draft read "before"; Samba source is also `>=` (inclusive) |
| LAB-LK-05 | Stored duration 0 and stored `MinInt64`, with `lockoutTime` 10 years old | injected | both: locked ("until unlocked") | n/a | Syn | Treating 0 as "no lockout" |
| LAB-LK-06 | Lock a user, then disable the account | `lockoutTime ≠ 0`, `ACCOUNTDISABLE` | Locked out **and** disabled, both shown | UF_LOCKOUT set | S | Hiding locked accounts that are disabled makes the count disagree with the DC |
| LAB-LK-07 | Unlock (write `lockoutTime = 0`), sync | `lockoutTime = 0` | Not locked on the next sync | UF_LOCKOUT clear | S | Unlock is `0`, so the input is "present and 0", not "absent" |
| LAB-LK-08 | Computer account and a trust-flag account carrying a non-zero `lockoutTime` | `uac` trust bits | Never "locked out" | UF_LOCKOUT clear | Syn (live: `W`, a client may not be able to write it) | R1 first clause |
| LAB-LK-09 | Row written before the D7 columns existed (`inputs_read` bit 1 clear) | not read | **Unknown (input missing)**, reason `lockout_time_not_read`; excluded by both a filter and its negation | n/a | Syn | "Not locked" as the default |
| LAB-LK-10 | Two DCs: lock on the PDC emulator, sync from another DC before replication | stale replica | Row shows "as of <time> from <DC>" and may be wrong until replication; count differs from the PDCe | PDCe UF_LOCKOUT | W (2-DC) | A single-DC Samba lab cannot show this; the `2dc` tier is not built ([ad-lab §8](../runbooks/ad-lab.md)) |

## 4. Fine-grained password policy (PSO) rows

PSO objects live in `CN=Password Settings Container,CN=System,<domain>`; links are
`msDS-PSOAppliesTo` on the PSO. Samba supports PSOs since 4.9
([release notes](https://www.samba.org/samba/history/samba-4.9.0.html)).

| ID | Setup | Expected resolved policy | Oracle | Run | Trap |
| --- | --- | --- | --- | --- | --- |
| LAB-PS-01 | PSO P1 (max age 30 d) linked directly to user U | P1, "Policy source: P1" | `msDS-ResultantPSO` = P1 | S | n/a |
| LAB-PS-02 | P1 linked to a global security group G; U ∈ G | P1 | same | S | n/a |
| LAB-PS-03 | P1 linked to G2; G1 ⊂ G2; U ∈ G1 (nested two deep) | P1 (transitive) | same | S | A one-level `member` join misses it |
| LAB-PS-04 | P1 linked to **Domain Users**; user created normally (primary group 513, not in `member`) | P1 for every normal user, including U | same | S | The primary-group edge: a `member`-only join misses everyone |
| LAB-PS-05 | P_direct (precedence 50) on U; P_group (precedence 1) on a group of U | **P_direct** | same | S | "Lowest precedence wins" applied across both sets |
| LAB-PS-06 | P_a (precedence 10) and P_b (precedence 20) on two groups of U | P_a (smaller number wins) | same | S | Reading "higher precedence" as a bigger number |
| LAB-PS-07 | P_a and P_b with **equal** precedence on two groups of U; create PSOs until the wire-byte order of their `objectGUID`s differs from the order of the GUID text form | Record which one wins on Windows; engine must match (currently: 16 raw wire bytes) | same | **W**; Samba `S*` | Samba's tie-break (`ndr_guid_compare`) may order GUID fields numerically; pass on Samba proves nothing about Windows. `[UNVERIFIED]` which order Windows uses |
| LAB-PS-08 | P1 linked to (a) a domain-local security group, (b) a universal security group, (c) a global **distribution** group, each containing U, one at a time | Windows decides per case; record. Current engine applies any group | same | **W**; Samba `S*` | Samba filters on "security-enabled, not built-in-local", so it will apply (a) and (b); Windows' guidance is "global security groups" `[UNVERIFIED]`. Resolves T-0958 deviation 4 |
| LAB-PS-09 | P1 on Domain Users; look at **krbtgt**, a computer, and a computer in a group P1 is linked to | No PSO on krbtgt (WS2019+ `[UNVERIFIED]`: "2016 and earlier do not enforce", per MS-ADTS note), none on computers; policy source "Domain policy" or "Not applicable" | `msDS-ResultantPSO` absent | S, W | A PSO name leaking onto a machine row |
| LAB-PS-10 | RODC `krbtgt_NNNNN` (`msDS-SecondaryKrbTgtNumber` set) with P1 on Domain Users | No PSO | absent | W (needs an RODC; not in the Samba lab) | Engine does not read `msDS-SecondaryKrbTgtNumber` today (follow-up, T-1016 note) |
| LAB-PS-11 | Edit P1's max age, then add U to another PSO group, then delete the link: re-run the report each time, **no write to U** | Each change reflected on the next run after the policy sync | `msDS-ResultantPSO` and `msDS-UserPasswordExpiryTimeComputed` | S | Any per-user cached PSO fails (D4) |
| LAB-PS-12 | Service account **without** read on the Password Settings Container, PSO exists and applies to U | **Unknown (input missing)**, reason `pso_set_not_read` or `pso_not_read`; never the domain policy and never "no PSOs" | `msDS-ResultantPSO` read as Domain Admin shows the PSO | S (deny ACE on the container), W | **LDAP returns an empty result, not an error, when read is denied**. An unreadable container looks identical to an empty one, so the D4 reader must prove readability (it cannot infer it from zero rows). The default read ACL is `[UNVERIFIED]`: Microsoft documents write rights and delegation, and vendors report service accounts failing to read the container |
| LAB-PS-13 | Domain functional level below 2008 (only if the lab can host it; else documentation) | PSOs have no effect: resultant PSO absent | n/a | W | The engine would otherwise apply a PSO the DC ignores |

## 5. Expiry rows (password and account)

Domain `maxPwdAge` 90 d unless the row says otherwise; `T` is the run's `now`.

| ID | Setup | Expected report state | Oracle | Run | Trap |
| --- | --- | --- | --- | --- | --- |
| LAB-PW-01 | `pwdLastSet = T − 10 d` | Expires at `pwdLastSet + 90 d`, 80 days remaining | `msDS-UserPasswordExpiryTimeComputed` equal to the engine's instant | S | Day rounding: compare instants, show days |
| LAB-PW-02 | `pwdLastSet = T − 91 d` | Password expired | PE `0x800000` set | S | n/a |
| LAB-PW-03 | `DONT_EXPIRE_PASSWORD` set, `pwdLastSet = T − 400 d` | Never expires (account flag) | PE clear, expiry `0x7FFF…` | S | Showing "expired" (seed has 2 % such users) |
| LAB-PW-04 | `DONT_EXPIRE_PASSWORD` set **and** `pwdLastSet = 0` | Never expires (account flag), **not** must-change | PE clear, expiry `0x7FFF…` | S | Row-order bug: must-change checked before the flag |
| LAB-PW-05 | `pwdLastSet = 0`, no flag | Must change at next logon, never labelled "expired" | **PE set**, expiry `0` | S | The DC sets PE for this user. Reconciliation: `count(PE) = must_change + expired` over non-exempt users (seed: 0.5 % + 2 %); an admin who filters ADUC by "password expired" must see the sum |
| LAB-PW-06 | `pwdLastSet` absent (user created without a password, if the DC allows it; record what each DC stores) | Must change (R2), distinct from "not read" | PE set | S*, W | Samba and Windows may store 0 instead of absent; the row records which, the engine must not care |
| LAB-PW-07 | `SMARTCARD_REQUIRED`, `pwdLastSet = T − 400 d` | Not applicable (smartcard required) | PE clear, expiry `0x7FFF…` | S, W | See PW-08 |
| LAB-PW-08 | As PW-07 at domain functional level 2016 with `msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE` | Record. Report keeps "Not applicable (smartcard required)" unless the lab shows PE set on Windows | PE and expiry on Windows | **W**; Samba `S*` | Samba computes a real expiry in this configuration; MS-ADTS says exempt. Disagreement means the Windows value decides |
| LAB-PW-09 | Domain `maxPwdAge` stored as exactly **0** (written by LDAP) | **Unknown (input missing)**, reason `domain_policy_not_read`/unverified value. Never "never" and never "expired" | Record Windows' computed expiry | Engine: Syn. DC oracle: W; Samba `S*` | Samba treats 0 as "never", so a Samba oracle would call this row "Never expires" and a naive comparison would pass the wrong answer. Keep Unknown until PW-11 shows what Windows does. The codec refusing 0 is correct |
| LAB-PW-10 | Domain `maxPwdAge` = `MinInt64` ("never" per MS-ADTS) | Never expires (policy) | expiry `0x7FFF…` | S | n/a |
| LAB-PW-11 | Set "never" through each tool: GPO "0 days", ADAC domain policy, `Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 0`, `New-ADFineGrainedPasswordPolicy -MaxPasswordAge 0`, `samba-tool domain passwordsettings set --max-pwd-age=0`. Read back the raw `maxPwdAge` / `msDS-MaximumPasswordAge` | Record the stored value per tool | n/a | **W** (Samba for its tool) | Decides whether stored 0 can ever occur; resolves open point (a) and (b). Until recorded, "stored 0 means never" in reports-2a §6.4 is unsupported |
| LAB-PW-12 | Boundary: `now = pwdLastSet + maxAge`, `+ 1 tick`, `− 1 tick` | not expired, **expired**, not expired (strict `>`) | n/a | Syn | Samba source is also strict (`<` on the expiry instant) |
| LAB-PW-13 | Lower the domain `maxPwdAge` from 90 d to 30 d for a user with `pwdLastSet = T − 50 d`; re-sync policy only, **no user write** | Password expired after the policy sync, not before | PE set after the change | S (then `lab-reset`) | D4: no per-user cache |
| LAB-PW-14 | PSO max age 30 d on U, domain 90 d, `pwdLastSet = T − 40 d` | Password expired, Policy source = PSO name | PE set | S | A domain-only evaluation says "50 days left" |
| LAB-PW-15 | Computer, trust account | Not applicable | expiry `0x7FFF…` | S | Machine password age is not "expired" |
| LAB-PW-16 | Any of PW-01…PW-05 with `pwdLastSet` input marked not read (`inputs_read` bit 2 clear) | Unknown (input missing), reason `pwd_last_set_not_read` | n/a | Syn | Absent and "not read" must differ |
| LAB-AX-01 | `accountExpires` = `T + 20 d` | Not expired; expires at that instant | n/a (no constructed attribute; the authentication result is the oracle: bind as that user after setting it to `T − 1 s`) | S | n/a |
| LAB-AX-02 | `accountExpires` = 0; `= 0x7FFFFFFFFFFFFFFF`; absent | all three: Account never expires | bind succeeds | S | Seed: 0 only for "once set, then cleared"; both occur |
| LAB-AX-03 | `accountExpires` = `T − 1 s`, then `T + 1 s` | Expired / not expired | bind fails with `STATUS_ACCOUNT_EXPIRED` / succeeds (LDAP 49, sub-code 701 `[UNVERIFIED]`) | S, W | Boundary instant itself is `[UNVERIFIED]`; test only 1 s either side |
| LAB-AX-04 | ADUC "End of <date>" on Windows; read the stored value | Record: stored instant is the following local midnight `[UNVERIFIED, secondary sources]` | n/a | W | Show the instant stored; never print "date − 1" |
| LAB-AX-05 | `accountExpires` negative, or above year 9999 | Negative: Unknown (invalid); above year 9999: "far future", not expired `[UNVERIFIED]` | n/a | Syn | Overflowing a date type |

## 6. Where Samba gives a false pass

1. **Stored 0 for `maxPwdAge`**: Samba says never (PW-09). Windows undocumented.
2. **Equal-precedence PSO tie-break** (PS-07): different comparison, possibly different winner.
3. **PSO via domain-local or universal group** (PS-08): Samba applies; Windows may not.
4. **Smartcard + 2016 level** (PW-08): Samba computes a real expiry.
5. **One DC**: no PDC-emulator lag or lockout-source split (LK-10).
6. **PSC read ACL** (PS-12): the lab service account is a delegated account, not Domain Admin, so
   the default Windows ACL may behave differently from the lab. Check by reading the ACL, not by assuming.

## 7. What the rows ask of the engine (for the owners)

- Rows LK-04, LK-05, PW-09, PW-12, LK-08, LK-09, PW-16, AX-05 are `Syn`: they belong in
  RP8 `Test_derived_columns_match_reference` (`directory/inventory`, T-0958). Several already exist
  there; the owner maps IDs to cases and lists the gaps.
- The live rows (`S`) need a seeded lab fixture of PSOs, groups and users with deterministic names
  (`lab/seed/generate.py`, which changes the seed version and needs a generator unit test, ad-lab §4).
  The Windows rows are recorded as a run log, with the raw oracle values.
- Follow-ups: T-1134 (directory-engineer: the gaps below) and T-1135 (test-engineer: seed, map and run the rows).
- Gaps found against the built engine: (1) `msDS-SecondaryKrbTgtNumber`
  not an input (PS-10); (2) the D4 reader cannot tell an unreadable container from an empty one (PS-12);
  (3) the PSO group scope filter is open until PS-08 runs; (4) the domain functional level is not an
  input (PS-13).

## Changelog

- 2026-10-31 · created (T-1016)
