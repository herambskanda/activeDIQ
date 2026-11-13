---
title: "TM-D34: the connector's own identity and activeDIQ service identities are Tier-0 to the connector (basis C20)"
date: 2026-11-07
updated: 2026-11-07
status: review
owner: heramb
author: security-architect
ticket: T-1643
binding_sources: threat-model TM-A1, TM-A2, §6.1, §6.4, §6.5, TM-D4, TM-D23, TM-D27, TM-D28; connector-contract §8.1, §8.3, §8.10; ad-forest-connection V7
---

# TM-D34: protecting the connector's own identity from our own write kinds

## 1. The threat

**Asset:** TM-A1/TM-A2, the connector identity's delegated rights (gMSA, or a keytab/password account on
`linux-oci`). It is the only directory identity (ADR-0002 rule 3) and holds every delegated right
outside our RBAC and audit trail.

**Attacker:** an activeDIQ operator who holds `objects.user.reset_password` (or `objects.account.disable`/`enable`)
but is *not* meant to hold the connector's rights: a help-desk technician, or an insider.

**Attack (TM-D34-T1, elevation):**
1. The connector's account (or another activeDIQ service account) is a `user` object. On a keytab/password
   profile it always is; on a gMSA profile the *host computer accounts* in
   `msDS-GroupMSAMembership` are computers (TM §6.1).
2. It sits in, or inherits from, an OU the connector has Reset Password on. This is the usual outcome of
   delegating at a high OU and parking the service account in the same tree.
3. The operator plans `USER_PASSWORD_RESET` against it. T-1583's connector guard accepts it: the target
   is not `tier0` (C1-C19 do not name the connector), the class is `user`, and the connector holds the
   right. `Apply` sets a password the operator knows.
4. The operator authenticates as the connector (not through our RBAC or audit), and holds every delegated
   right (TM-A1) from any host that reaches a DC.

**Related attacks through the same hole (TM-D34-T2..T4):**
- *T2, denial of service:* `ACCOUNT_DISABLE` on the connector account, or on the connector host's
  computer account, stops every feature of every connection. CC-WK-27 as written refuses it only if the
  identity is already Tier-0, which the contract tells customers it must not be (TM-D1).
- *T3, `ACCOUNT_ENABLE`* re-opens a service account the customer disabled on purpose (incident response).
- *T4, the other kinds* (`OBJECT_UPDATE`, `MOVE`, `RENAME`, `DELETE`, `RESTORE`) aimed at the same object:
  writing `servicePrincipalName`, `altSecurityIdentities` or a key credential gives the same takeover
  as a reset, whatever the attribute deny-list says today; a move into an OU an attacker controls or a
  delete is availability loss. A rule on three kinds would leave these open.
- *T5, a target with the connector's SID in its `sIDHistory`* carries the connector's token on logon.

## 2. Decision

**Make the connector's own identity, and the registered activeDIQ service identities, `tier0` in the
connector's set, with a new basis C20.** Not a refusal written into three kinds.

Why this and not "refuse in kinds 7, 9, 10":

| Option | Verdict |
| --- | --- |
| Kind-specific refusal in the account guard | **Rejected.** Covers three of ten kinds; every future kind (membership, SD edit, group nesting) must remember it. This is the "remember to label it" failure TM-D28 exists to prevent |
| Server-side only (RBAC / UI hides the row) | **Rejected as the only control.** ADR-0005 rule 7: the server guard is a second layer; the connector is the one that cannot be talked out of a refusal by a bad request |
| **C20 in the connector's `tier0` set** | **Chosen.** One refusal path for every kind present and future (CC-WK-28 already iterates every kind), live re-read, ratchet, and `TIER0_REFUSED` before any directory call. `Plan` refuses too (reads only) so the console shows the reason instead of a dead button |

### 2.1 Definition of C20

An object X is `tier0`, basis **C20 (connector-controlled identity)**, when any of:

| # | Rule | Source of the fact | Class |
| --- | --- | --- | --- |
| a | X is the **connector's bound principal**: X's `objectGUID` or `objectSid` equals the principal's, or X's token (`objectSid` + every `sIDHistory` SID) contains the principal's SID | The connector itself, from the *bound session*, never from the request, the config text or the server | **live** |
| b | X is a principal in the bound gMSA's `msDS-GroupMSAMembership` (the host computer accounts), or the gMSA itself, or on keytab profiles the keytab account (same as a) | Read live from the gMSA object | **live** |
| c | X is a **registered activeDIQ service identity** in this directory: the bound principals of the other connections to the same forest, the server's service account/gMSA, and (M3/M4) the DC-agent, file-agent and SSPR bind accounts | The server's registry, sent in the `Tier0Context` as designations with reason `ACTIVEDIQ_SERVICE`. Additive-only like F2 | **context** |
| d | The principal cannot be resolved, or resolves to anything but exactly one object, or any read for a, b fails | n/a | **unknown is `tier0`**, basis `UNKNOWN` (as C17) |

**How the connector learns its own principal (rule a).** LDAP Who am I
([RFC 4532](https://www.rfc-editor.org/rfc/rfc4532)) on the pinned, bound session returns the authorisation
identity. The connector resolves that to an object with a filter from the filter builder
(safe-primitives §3), reads `objectGUID` and `objectSid`, and requires exactly one match. This is the **same
resolution** V7 and `rights.StreamAD` use for the identity (`identity dn.ObjectRef`); there is one
function, called by both, so the write guard and the over-privilege check cannot disagree. A `u:` or
`dn:` form that does not resolve to one object makes **every account write** `TIER0_REFUSED` (rule d),
not "no match, so allowed". Config text (the account name in the connection form) is never an input:
a renamed or aliased account must not escape.

**Rule c is a context basis and inherits R-T0CTX-1.** A server that omits a service identity cannot be
detected by the connector. The connector's own identity (a, b) is never subject to that residual
because it needs no server input. Detective control: the connector logs the count of `ACTIVEDIQ_SERVICE`
designations with each `Plan`/`Apply` (as F6 does for `tier0_revision`).

### 2.2 Refusal contract

- **Code and stage:** `TIER0_REFUSED`, stage `CONNECTOR_SET` (§8.1 step 4) for a, b, c-from-context; `LIVE_REREAD` (step 7)
  when the live read finds it. Basis `C20_CONNECTOR_IDENTITY` (proto: `TIER0_BASIS_C20_CONNECTOR_IDENTITY = 20`).
- **Before any directory write.** It comes at step 4 or 7 of §8.1, before the kind's code, so the
  target check precedes `ClassNotAllowed`: a reset on the connector's computer account answers C20, not
  "wrong class" (§8.1 "why the target check precedes the kind check").
- **All kinds, Plan and Apply**, including `ACCOUNT_DISABLE` (CC-WK-27 no longer depends on the identity
  being Tier-0 by another basis) and `ACCOUNT_ENABLE`. No override: C20 is not in the override path
  (§8.2); the connector does not read it.
- **Fixed text,** no echo of identity names: "This account is activeDIQ's own service identity and cannot be changed by activeDIQ".
- **Attempts are audited and alerted.** The server records `tier0_refused` with actor and basis C20 and raises a
  security alert of the same severity as a Tier-0 attempt: nobody legitimate plans this.
- **UI:** the object shows a "protected: activeDIQ service identity" state; its write actions are disabled with that
  reason (no dead buttons).

## 3. V-check: the identity must not control itself

Add **V7e** to the V7 over-privilege check (spec `ad-forest-connection.md` V7; TM §6.5 gains step 6). Run
as the connector, from the directory (never from the process token), on the bound principal's own
object and on each rule b/c object that is readable:

| Finding | Result | Fix text |
| --- | --- | --- |
| The identity's object lies **inside any `managed_roots`** of the connection | **Fail, not overridable** (placement is a one-move fix; an in-scope service account is what makes T1 reachable) | Move the account to an OU outside every managed root |
| The identity's token holds an allow ACE on its own object (or on the host computer accounts) with the **Reset Password** control access right (`00299570-246d-11d0-a768-00aa006e0529`), `WriteProperty` on `unicodePwd` or `userAccountControl`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_ALL`/`GENERIC_WRITE`, or an all-properties `WriteProperty` | **Warn** with fix (blocks only through V7 if the object is `tier0`) | Move out of the delegated tree, or add an explicit deny ACE for the identity's own SID |
| Own object unreadable, SD flagged `Unknown`, callback ACE | **Could not verify** | n/a |

Typed ACEs from the security-descriptor primitive (T-0149), never SDDL strings; the effective-rights helper
is the one the classifier uses. A gMSA is checked the same way (a gMSA's password is not settable by
`unicodePwd`, but WRITE_DAC/OWNER matter).

## 4. Threat table (STRIDE slice: server → connector → DC, account kinds)

| ID | STRIDE | Threat | Mitigation | Proving test | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-D34-T1 | E | Reset of the connector's own account, then sign-in as it | C20 a; refusal before write | CC-WK-27, 36 | none for a; rule c is R-T0CTX-1 |
| TM-D34-T2 | D | Disable of the connector account or host computer account | C20 a, b | CC-WK-27, 37 | none |
| TM-D34-T3 | T | Enable of a service account the customer disabled | C20 (all kinds) | CC-WK-36 | none |
| TM-D34-T4 | E/D | Update/move/rename/delete/restore of the same object | C20 is a basis, not a kind rule | CC-WK-28 (every kind), 38 | none |
| TM-D34-T5 | E | Target carries the connector's SID in `sIDHistory` | C20 a, token clause | CC-WK-38 | `sIDHistory` unreadable counts as `tier0` |
| TM-D34-T6 | S | Connector cannot determine who it is, guard fails open | C20 d; whole account-write family refused | CC-WK-39 | availability: a Who am I outage blocks account writes (accepted; fail closed) |
| TM-D34-T7 | E | A second connection's bind account or the server gMSA is not known to this connector | C20 c via context; the server's guard refuses from the same registry | CC-WK-37 | R-T0CTX-1: a server that omits the entry is not detectable. Narrowed because the server guard and V7e's placement rule cover the common case |
| TM-D34-T8 | I | Refusal text leaks which accounts are service identities | Fixed text, basis only. The operator already sees the object they picked | CC-WK-36 (assert text) | The existence of the protected state on a known object is visible; accepted, the object is already listed to them |
| TM-D34-T9 | R | Attempts invisible | `tier0_refused` audit and alert | server audit test | none |
| TM-D34-T10 | E | The service account is inside the managed scope and V7e is overridden | V7e placement is **not overridable**; C20 still refuses at write time | CC-WK-40 | none |

**Not covered here (filed as a follow-up):** objects that *grant* the connector its rights without being it: groups that are
trustees of its delegation ACEs, and OUs whose DACL it owns. Editing those is the same attack by another
route (add yourself to the delegation group). No membership kind exists yet in the first ten; the ticket
below must land before one is wired.

## 5. Contract changes (landed in connector-contract with this ticket)

- §8.1 per-basis table: new row **C20**; §8.10.3 kinds 7, 9, 10 gain the refusal line; CC-WK-27 rewritten;
  CC-WK-28 extended; CC-WK-36 to 40 added; amendment line. The proto change (`TIER0_BASIS_C20_CONNECTOR_IDENTITY`, `ACTIVEDIQ_SERVICE`
  designation reason, `VerifyConnection.completed` carrying the bound principal GUID and SID for the server registry) is the
  build ticket's, and `make fitness-proto` gates it.
- The connector never links the server's registry; it receives designations only (P-rules unchanged).

## 6. Fitness function

`TM-F-SELFID` (new, in the CC-WK-28 test): for **every** `kindTable` row, a plan and an apply against
(1) the bound principal, (2) a gMSA retrieval-list computer account, (3) a context-designated service identity, each answering `TIER0_REFUSED`
basis C20 with the proxy showing **zero** write requests. Because it iterates `kindTable`, a kind added later is covered
or the test fails. Runs on Samba in CI (S); the Windows lab (W) repeats (1) and (2) for the gMSA profile. Until the build ticket lands the
case is a failing test, so TM-D34 stays `review`, not `accepted`.

## 7. Sources

- Who am I extended operation: [RFC 4532](https://www.rfc-editor.org/rfc/rfc4532)
- Reset Password is a control access right checked for `unicodePwd` set: [unicodePwd](https://learn.microsoft.com/en-us/windows/win32/adschema/a-unicodepwd)
- `msDS-GroupMSAMembership` as the retrieval list: [gMSA](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)
- Competitor context (ManageEngine's record of delegated-account compromise): `knowledge/business/market-research/manageengine-ad-customer-voice-and-security.md`
- Internal: threat-model TM-A1/TM-A2, §6.1, §6.4, §6.5, TM-D28; connector-contract §8.1, §8.10.
- `[UNVERIFIED Windows]`: that Who am I returns `u:` (UPN/SAM) for a Kerberos GSSAPI bind and `dn:` for simple binds on Windows Server 2019-2025; CC-WK-39 W decides, and the resolution code must accept both.
