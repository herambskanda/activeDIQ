---
title: "Group member add/remove and computer account reset: sourced and measured findings (kinds 11-13)"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: ad-expert
author: ad-expert
ticket: T-1919
---

# Kinds 11-13: what is sourced, what is measured, what still needs Windows

Scope: the five `[UNVERIFIED Windows]` items of connector-contract §8.10.3 kinds 11-13 (T-1899). **No Windows
DC was available in this run** (only the Samba lab). Each item is therefore one of: *measured on Samba*,
*sourced to Microsoft documentation*, or *still needs the Windows run* with the question narrowed.
Measurements: Samba 4 lab (`make lab-up`, 2026-11-14), `ldapadd`/`ldapmodify` over LDAPS as `Administrator`.

## Verdict table

| # | Item | Result | Status |
| --- | --- | --- | --- |
| 1 | Scope-rule result code (kind 11, CC-WK-51) | Windows rejects the nest and names the failure by a Win32 code; the LDAP result code is not in any spec page we could fetch. **Samba accepts the add**, so a Samba pass of `GroupScopeRule` is a false pass | Win32 codes sourced; LDAP code `[UNVERIFIED Windows]`; Samba measured |
| 2 | Loop acceptance (`NestingCycle`) | **Samba accepts both a loop and a group as its own member.** Windows behaviour not documented in MS-ADTS/MS-SAMR; keep our refusal, keep the tag | Samba measured; Windows `[UNVERIFIED]` |
| 3 | Cluster SPN detection (CC-WK-59) | `MSClusterVirtualServer` is the reliable marker (Microsoft's own guidance uses it to find CNOs and VCOs). `MSServerClusterMgmtAPI` is secondary-sourced and not shown to be on every object | Partly sourced; CNO/VCO split `[UNVERIFIED Windows]` |
| 4 | Machine-side repair rights | Microsoft documents `-Credential` as "a user account that has permission"; the exact ACE is not documented there | Partly sourced; exact right `[UNVERIFIED Windows]` |
| 5 | Samba computer reset (CC-WK-57) | Measured: works as the contract assumes | **Measured, cleared** |

## 1. Scope rule (kind 11)

- Windows defines the failures as Win32 errors: 8516 `ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER`, 8517 `…_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER`,
  8518 `ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER`, 8519 `…_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER`, 8520 `…_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER`,
  8514/8515 `ERROR_DS_NO_NEST_GLOBALGROUP/LOCALGROUP_IN_MIXEDDOMAIN`
  ([System Error Codes 8200-8999](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--8200-8999-)).
  The contract's `unwillingToPerform` mapping is consistent with how MS-ADTS maps group-type violations on
  other operations (for example Modify DN returns `unwillingToPerform` / `ERROR_DS_CANT_MOVE_ACCOUNT_GROUP`,
  [MS-ADTS Modify DN constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ddfd32cf-615c-4e98-9d8f-e490e13c3c71)),
  but **no MS-ADTS or MS-SAMR page we read states the LDAP result code for a `member` add** (MS-ADTS 3.1.1.5.3.2
  and MS-SAMR 3.1.1.6 have no membership-scope rule). Microsoft's own scope matrix says a domain-local group cannot be
  a member of a global or universal group
  ([Security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)).
- **Measured on Samba:** a domain-local group added to a global group, a global group added to a domain-local
  and a universal group, and a global into a global: all returned success and are stored in `member`.
  Samba enforces no scope rule on LDAP `member` writes. **A CC-WK-51 run on Samba proves nothing about
  `GroupScopeRule`**: the test must be W-only, or the connector must apply the matrix itself (which would be a
  product decision; today it relies on the DC's refusal).
- Contract consequence: the engineer cannot key the rule on one result code. Treat `unwillingToPerform` (53) as
  the expected code, keep matching on the *refusal*, and record the actual code and Win32 detail text from the
  Windows run (the DC's extended error text carries the Win32 code; fixed product text must not echo it).

## 2. Loops and self-membership (kind 11)

- Measured on Samba: `GG2 ∈ GG` and `GG ∈ GG2` both stored (a loop); `GG ∈ GG` stored (self-member). The
  contract's `SelfMembership` comment "AD refuses a group as its own member" is **not true of Samba** and
  not shown in a Microsoft document; do not rely on the DC for either refusal. Both pre-checks stay
  product-side, and tests for them on Samba are valid *because* the DC does not refuse (the test proves our
  refusal, not AD's).
- Windows: unknown. Token-expansion handles cycles (`tokenGroups` is computed, nested lookups by
  `LDAP_MATCHING_RULE_IN_CHAIN` terminate), so a loop is survivable but is an admin hazard. `[UNVERIFIED Windows]`.

## 3. Cluster SPN detection (kind 13)

- Microsoft's Core Infrastructure guidance finds cluster computer objects by "a service principal name (SPN) of
  `MSClusterVirtualServer`" and says CNO and VCO share the marker
  ([Identifying stale cluster computer objects](https://thewindowsupdate.com/2019/10/07/identifying-stale-cluster-computer-objects/),
  republished from the Microsoft blog; secondary). CNO and VCO definitions:
  [Configure failover cluster accounts](https://learn.microsoft.com/en-us/windows-server/failover-clustering/configure-ad-accounts).
- `MSServerClusterMgmtAPI` is listed as "needed for cluster APIs to authenticate to the server by using Kerberos"
  ([ADSecurity SPN list](https://adsecurity.org/?p=183), secondary) and `MSServerCluster` points to KB 302389.
  Whether `MSServerClusterMgmtAPI` is on the CNO only, or on every VCO, is not documented `[UNVERIFIED Windows]`.
- **Recommendation:** detect on `servicePrincipalName` having a value starting `MSClusterVirtualServer/` *or*
  `MSServerClusterMgmtAPI/` or `MSServerCluster/` (case-insensitive; SPN class is case-insensitive). Accept
  the false-negative window: a **prestaged** cluster account (disabled, created before the wizard, per the Learn
  prestage steps above) has **no SPN yet** and passes the check. The Plan should say so and warn on a disabled
  computer whose name matches the cluster naming pattern. The lookalike negative in CC-WK-59 is valid.
- Measured on Samba: SPNs of those classes can be written and the filter
  `(servicePrincipalName=MSClusterVirtualServer/*)` finds the object, so the **filter and the `ClusterObject` refusal can
  be tested on Samba** with a hand-made SPN; only "a real cluster writes this SPN" needs Windows.

## 4. Machine-side repair rights (kind 13)

- `Reset-ComputerMachinePassword` and `Test-ComputerSecureChannel -Repair` take `-Credential` "a user account that
  has permission to perform this action"
  ([Reset-ComputerMachinePassword](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword),
  [Test-ComputerSecureChannel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-computersecurechannel)).
  The specific ACE (the *Reset Password* control access right, plus write of the account-restriction property set,
  is the usual reading) is **not stated**; keep the contract wording "credentials that have Reset Password on the
  object" tagged `[UNVERIFIED Windows]` and let CC-WK-57's W run test it with a delegated, non-admin account.
- Contract text is otherwise consistent: the repair is machine-side and not an LDAP write.

## 5. Samba computer reset (kind 13) — measured, cleared

Computer `T1919PC` (UAC 4096) created with a known password, then `replace unicodePwd` with a 120-character random
value over LDAPS as Administrator:

| Observation | Result |
| --- | --- |
| Reset result | success; `uSNChanged` 22693 → 22695 |
| `pwdLastSet` | advanced (134391466254225253 → 134391466277465831) |
| Bind as `T1919PC$` with the **old** password | refused, `80090308 … data 52e` (invalid credentials) |
| Bind with the **new** password | success |
| UAC, object, SID | unchanged (4096) |
| A name-derived value (`t1919pc`) and a 3-character value | **accepted** on Samba: no complexity or length rule for a workstation-trust account |

- The Samba lab therefore **supports the CC-WK-57 assertions** (replace, `pwdLastSet` advance, old password fails,
  new works). A simple LDAP bind as the computer account is the oracle; on Windows the secure-channel check
  (`Test-ComputerSecureChannel`) is the true oracle.
- Samba acceptance of a name-derived password says nothing on Windows; the "no known value" rule is our decision.
  The ADUC "reset to the computer name" claim stays `[UNVERIFIED]` (source is an O'Reilly cookbook).
- Domain password policy on a machine account's `unicodePwd` write over Windows is `[UNVERIFIED Windows]` (a 120-char
  random value is long and complex either way).

## Side finding: compare-and-set result codes on Samba (a trap for kind 12)

Measured on Samba: `add member` of a present value → `attributeOrValueExists` (68, "Attribute member already
exists"), as the contract says. **`delete member` of an absent value → `unwillingToPerform` (53, "Attribute
member doesn't exist"), not `noSuchAttribute` (16).** The contract's mapping (kind 12 §"Compare-and-set") names
`noSuchAttribute`; the connector must accept 16 *or* 53-with-absent-value and resolve it by the member-side read
(`ALREADY_APPLIED` when `memberOf` lacks the group). What Windows returns is `[UNVERIFIED Windows]`.

## For the engineer

1. `GroupScopeRule` and `SelfMembership`/`NestingCycle` tests on Samba cannot prove the DC's behaviour. Write
   them as product-side refusals (tests assert nothing is sent) and keep the W case for the DC refusal.
2. Cluster detection: SPN-class filter; document the prestaged-account blind spot.
3. Kind 13 on Samba is testable end to end; use a bind as the computer as the check.

## Still open (carried by the Windows lab, CC-WK-51, 57, 59)

LDAP result code and Win32 text for a scope violation; whether Windows accepts a loop; which cluster SPN classes sit
on CNO vs VCO; the minimum delegated right for machine-side repair; machine-password policy on `unicodePwd`.
