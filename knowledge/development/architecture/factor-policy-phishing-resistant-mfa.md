---
title: "Factor policy: phishing-resistant MFA enforcement at AN-10"
date: 2026-10-29
updated: 2026-10-29
status: draft
owner: security-architect
author: security-architect
ticket: T-0574
binding_sources: threat-model.md (review) §7.2, AN-8..AN-10 rules 1-3, TM-D19; console-sso.md MFA-5; domain-model.md DM-30, DM-33.I3, DM-37
sources_last_checked: 2026-10-29
---

# Factor policy: phishing-resistant MFA enforcement

**Problem.** TM §7.2 makes WebAuthn the preferred factor, but AN-10 lets any enrolled factor finish
a pending sign-in. For an account that owns a passkey, TOTP is a downgrade path: a real-time
phishing proxy relays the password and the six digits, and the session is minted. The passkey adds
nothing while TOTP stays accepted. Real-time phishing proxies beating TOTP is already named in
TM-TB1-T1 as residual.

## 1. What the standards say

| Source | Statement | Use here |
| --- | --- | --- |
| [NIST SP 800-63B-4 §3.2.5](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) | Phishing resistance is cryptographic authentication with channel binding or verifier-name binding (WebAuthn is the cited example). Manually entered authenticator outputs, so TOTP, are not phishing-resistant | TOTP and WebAuthn are different classes, not interchangeable strengths |
| [SP 800-63B-4 §2, AAL2](https://pages.nist.gov/800-63-4/sp800-63b/aal/) | Verifiers SHALL offer at least one phishing-resistant option at AAL2; phishing resistance is "Recommended; must be available" | Every tenant gets WebAuthn; TOTP stays allowed for accounts without a passkey |
| SP 800-63B-4 §2, AAL3 (same page) | AAL3 authenticators SHALL have a non-exportable private key and SHALL provide phishing resistance (Table 1: Required) | Defines our optional strict tier (§3.4) |
| SP 800-63B-4 §3.2.13 (authenticators page above) | Syncable keys are inherently exportable, so they do not meet the AAL3 key requirement as written | A synced passkey is phishing-resistant but not AAL3 |
| [CISA, Implementing Phishing-Resistant MFA (Oct 2022)](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf) | Per secondary summaries, the widely available phishing-resistant method is FIDO/WebAuthn, PKI/smart card is the other; app-based, SMS and voice MFA are called out as vulnerable; number matching is an interim measure, not phishing-resistant ([summary](https://www.bricker.com/hitech-law/cisa-guidance-discourages-use-of-app-based-sms-and-voice-mfas-and-encourages-phishing-resistant-mfas)). `[UNVERIFIED — the PDF text could not be extracted by our fetch tool; re-read the primary before quoting it externally, including any "prioritise privileged users" wording]` | Supports "TOTP is the weaker class" |

Mapping, stated plainly: **activeDIQ's `phishing_resistant` factor class = WebAuthn with RP-ID
binding and user verification required. That meets the AAL2 phishing-resistant option. It meets
AAL3 only for hardware-bound (non-exportable) keys, which the optional strict tier checks.** We do
not claim AAL3 for the default tier. PIV/smart-card sign-in is not in v1.

## 2. Decision

**D-FP1 — Effective requirement is the strictest of four inputs.** At AN-10, an account is
`phishing_resistant_only` if **any** of these holds. Nothing can lower another input.

| # | Input | Rule | Who can change it |
| --- | --- | --- | --- |
| P1 | **Passkey lock** (per account, automatic) | The account has an `active` `webauthn` enrollment (DM-37) | Nobody directly. Ends only when the last `webauthn` enrollment is revoked, which is itself guarded (§4) |
| P2 | **Privileged role** | The account holds `tenant-owner` or any `control_plane` permission (DM-33.I3), or any delegation touching `tier0`/`adminCount=1` objects (§6.4) | Defined by us; the tenant may widen it (P3), never narrow it |
| P3 | **Tenant setting** `authn.require_phishing_resistant` = `off` / `privileged` / `all` | `privileged` is P2's set plus roles the tenant lists; `all` is every console account | `tenant-owner`, step-up (§7.4), audited, alerts all owners. Lowering it is also step-up |
| P4 | **Strict tier** (`hardware_bound`) | Optional per P2/P3 scope: only a WebAuthn credential whose authenticator data has the backup-eligible flag **clear** (BE=0) counts. `[UNVERIFIED — confirm the flag is exposed by the chosen WebAuthn library, RT-15]` | Same as P3 |

**D-FP2 — Default for new tenants:** P1 on; P3 = `privileged` with a **14-day enrolment grace**
for accounts that hold no passkey yet (grace applies to P2/P3 only, never to P1, and ends sooner
if the account gains a passkey). During grace the account may complete AN-10 with TOTP and every
sign-in shows an enrol-a-passkey banner and audits `authn.signin.grace_used`. After grace, an
account in scope with no passkey cannot finish AN-10; it can reach only the passkey enrolment
page, in a **restricted pending session** (no console permissions), after a TOTP + first factor,
so it can fix itself. A tenant that ratifies a different default does so in business terms (see
§7).

**D-FP3 — Refusal behaviour at AN-10.** For an account under `phishing_resistant_only`:

1. `verifyTotpSignIn` returns the **same uniform `401`** (status, body, headers, timing class) as a
   wrong code. The code is **not evaluated**: evaluating it would make the endpoint an oracle for
   "your TOTP seed is valid", would spend a TOTP step, and would charge the enrollment's DM-37.I5
   budget for an attempt that is policy, not guessing.
2. The attempt **is charged to the pending sign-in's 5-attempt budget** (AN-10 rule 1) so a relay
   cannot probe forever.
3. Audit event `authn.signin.factor_refused_policy` with account, factor class tried, policy
   input(s) that applied (P1..P4), pending-sign-in id, source IP. This is audited **whether or not
   the code was right**, because we do not look.
4. **Signal.** A refused TOTP for an account whose first factor just succeeded is a plausible
   phishing relay or a user on a stale habit. 3 in 1 hour for one account raises an alert to the
   account and every `tenant-owner` (and to the security-contact list). The alert text must not
   say the code was valid.
5. The factor choices shown on the second-factor page come from the pending-sign-in record, which
   exists only after a valid first factor, so listing "passkey only" leaks nothing that AN-8/AN-9
   enumeration resistance (rule 2) protects.
6. SMS/email OTP (DM-37 methods) are treated as TOTP: never phishing-resistant.

**D-FP4 — SSO.** An IdP-asserted MFA (console-sso MFA-5) is **not** phishing-resistant evidence
(`amr`/AuthnContext values vary and we cannot see the authenticator). For an account under
P1–P4: `MFAAsserted` does not skip AN-10; the pending sign-in demands a WebAuthn assertion held by
activeDIQ. P1 therefore applies to `sso` accounts that enrolled a passkey (this is also the TM-D19
authority factor, so those accounts already have a reason to). A later "phishing-resistant-asserting
IdP" flag is out of scope (`[OPEN]`, needs a vendor-specific proof design).

**D-FP5 — Break-glass (AN-8).**
- Break-glass accounts are **in scope of P1 but not of P2/P3**. They are availability-critical and
  already carry throttling without lockout, CIDR allow-list, owner alerts on every use (AN-8 rules 3–4, TM §7.2).
- A break-glass account holds **either** TOTP **or** a passkey, never a working mix: enrolling a
  passkey on it triggers P1 and TOTP stops working. The enrolment UI says so before confirming.
- Recommended practice (documented, not enforced): break-glass = two device-bound passkeys on
  hardware keys kept in separate safes. TOTP-only break-glass is a documented, accepted residual:
  phishable, but not reachable from outside the CIDR allow-list and every use alerts owners.
- Disabling AN-8 and the AN-8 policy exemption are different switches; a tenant on `all` still
  exempts AN-8 accounts from P3 and says so in the settings page. Making them in scope is possible
  only by the account enrolling a passkey (P1).

## 3. Anti-downgrade and recovery

1. **Removing the last passkey is the downgrade.** Revoking a `webauthn` enrollment that is the
   account's last one is allowed only (a) from a session that verified that same factor
   (DM-37.I4), or (b) by a `tenant-owner` reset with step-up. Either way: audited, the account and
   all owners are notified, and a **24-hour cooling period** follows during which the account
   still counts under P1 (so TOTP does not resume at once) and cannot be given the grace of
   D-FP2. Cooling is skipped only for case (a) when another `webauthn` enrolment remains.
2. **Enrolment of a passkey needs step-up** (the account's current factor), never the first
   factor alone, so a phished password alone cannot add an attacker's key. For the first passkey of
   an account with TOTP, step-up is the TOTP code; this is the one place TOTP gates a
   security-raising change and it is acceptable because it raises strength.
3. **An attacker with a TOTP-only session cannot be created under P2/P3 after grace** (no session
   exists without a passkey), so the downgrade cannot be started from a relayed TOTP.
4. **Lockout from lost passkeys.** UI nudges every account to hold **two** passkeys. Recovery for a
   non-owner: a `tenant-owner` resets (step-up, DM-37.I4). For an owner: another owner resets. For
   the **sole owner** with no passkey and no other owner: recovery is a host-local administrative
   command on the server (`[OPEN → follow-up T-0785]`), requiring OS administrator on the
   activeDIQ host, audited at next start. The break-glass account (D-FP5) is the other route.
5. The pending-sign-in handle never carries a "factor class" claim from the client; the server
   derives the policy from the account at AN-10 time, not at AN-8/AN-9 time, so a policy change
   between the two steps takes effect.
6. TOTP **enrolment** stays allowed (the account may still need it before it owns a passkey, and
   for end-user FD-05 enrolment, which is out of scope here: end users are not console accounts).

## 4. Threats this policy answers

| Id | Threat | Mitigation | Test that proves it | Residual |
| --- | --- | --- | --- | --- |
| FP-T1 | Proxy phishing relays password and TOTP | P1–P4; TOTP refused at AN-10 | `TestAN10TOTPRefusedWhenPasskeyActive` (valid code, 401, audit row, no session) | A relay of the WebAuthn flow fails by RP-ID binding; user on a phishing domain cannot produce a valid assertion |
| FP-T2 | Policy enumeration/oracle via refusal | Uniform 401, code not evaluated | `TestAN10PolicyRefusalIdenticalToWrongCode` (byte-identical status, body, headers; timing within the AN-8 class) | Second-factor page lists passkey only after valid first factor (D-FP3.5) |
| FP-T3 | Attacker downgrades by revoking the passkey | §3.1 guard + cooling | `TestRevokeLastPasskeyNeedsSameFactorOrOwnerStepUp`, `TestCoolingKeepsPasskeyLock` | A real owner with step-up can always reset (by design) |
| FP-T4 | Attacker enrols own passkey after phishing password | §3.2 step-up | `TestPasskeyEnrolRequiresStepUp` | Attacker with live relayed TOTP session pre-grace; the 14-day grace is a window (D-FP2) |
| FP-T5 | Compromised IdP asserts MFA for an owner | MFA-5 + D-FP4 | `TestSSOMfaAssertedStillRequiresPasskeyUnderPolicy` | None beyond MFA-5 |
| FP-T6 | Policy setting lowered by attacker with a session | P3 changes need step-up, alert all owners, audited | `TestLoweringTenantFactorPolicyNeedsStepUp` | Owner session with step-up is trusted |
| FP-T7 | Break-glass used as the downgrade path (TOTP break-glass account with high privilege) | D-FP5: AN-8 exemption only for the break-glass kind, alert on every use, CIDR | `TestBreakGlassNotExemptWhenPasskeyEnrolled` | TOTP-only break-glass remains phishable; accepted, documented |
| FP-T8 | Race: TOTP completes while a passkey is being activated | Policy evaluated in the same transaction as consuming the pending sign-in, under the account row lock | `TestAN10PolicyRaceActivationVsTOTP` | None |

## 5. Fitness function (rule 4: required before any ADR on this goes `accepted`)

`fitness-authn-factor-policy`, run in CI:
1. Parse the AN-10 handlers: every code path that mints a session from `verifyTotpSignIn` must
   call `FactorPolicy.Allows(account, method)` first. A TOTP/OTP verification function with no call
   to it fails the build.
2. The refusal must use the same error constructor as a wrong code (AST check: no distinct
   status, type or detail).
3. The test names in §4 exist and pass; an acceptance-criterion test (T-0574 AC1) exists:
   given a P1 account, a **valid** TOTP at AN-10 yields the uniform `401`, an audit row
   `authn.signin.factor_refused_policy`, and no session row.

## 6. Open points and tickets

- Build: `FactorPolicy`, AN-10 enforcement, grace, restricted pending session, alerts, settings
  page, fitness function. Filed as T-0784 (backend-engineer, security-sensitive).
- Host-local sole-owner recovery command. Filed as T-0785 (spec).
- Threat model §7.2 edited to point here (done in this ticket).

## 7. Directional items for the director

One item changes what customers experience and is therefore the CEO's in business terms; the
rest is mechanics I decided:

- **Default posture.** Recommended: "owners and Tier-0 delegates must use a passkey after 14 days;
  any account that owns a passkey can't be phished with a six-digit code." Cost to customers: each
  owner needs a passkey-capable device (platform authenticator or a ~USD 25–60 security key
  `[UNVERIFIED]`). Alternative: default `off` for P2/P3 with a prominent recommendation, selling
  weaker security. I recommend the first and will treat it as ratified unless the director routes
  it to the CEO; P1 (automatic) is a pure hardening with no customer-visible cost beyond recovery
  discipline, and is decided here.
