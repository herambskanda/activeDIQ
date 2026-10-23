---
title: "Spec: ENH-09 caller verification — OTP rules and the v1 TOTP enrolment page"
date: 2026-10-23
updated: 2026-10-23
status: draft
owner: heramb
author: product-manager
ticket: T-0192
epic: E-001
milestone: M2
parity: [ADM-142, ADM-136]
scope: locked
sources_last_checked: 2026-10-23
---

# Spec: ENH-09 OTP rules and the v1 TOTP enrolment page

> A help-desk technician with no AD rights cannot reset or unlock until the caller proves they are
> the user, with a code that is short-lived, single-use and guess-proof. An attacker who already
> holds the user's password cannot quietly enrol a factor of their own to pass that check.

Closes `[OPEN → ENH-09 spec]` of TM-TB1-T13 and fixes the OTP rules TM-F-ABUSE tests (TM-TB11-T2,
TM-TB1-T9). Input to the `platform/authn` and `modules/helpdesk` build tickets (T-0073 and later)
and to `solution-architect` for the DM-37/DM-38 changes in §9. Reviewed by `solution-architect`.
Tag all build tickets from this spec `security-sensitive`.

Scope anchors: ENH-09 and FD-05 in
[v1-scope-options.md](../../business/scoping/v1-scope-options.md) (v1 factors: one-time codes to
email or mobile numbers already held in AD/HR, plus a minimal end-user TOTP enrolment page; push
is M4; the full SSPR portal is not v1).

## 1. Problem and user

- **Help-desk lead and technician (tier 1, no AD rights).** Resets and unlocks are the most-run
  help-desk jobs. Voice phishing is the #2 initial-access vector at 11% (Mandiant M-Trends 2026,
  cited in [ENH-09](../../business/strategy/enhancement-catalog.md)); CISA AA23-320A describes
  help-desk resets and MFA transfers as the path. Today in ManageEngine, help-desk-assisted reset
  for ADSelfService Plus requires ADManager Plus as well (ADSS W9 in the same catalogue entry),
  and ADManager Plus's reset console has no caller verification (matrix ADM-136 note: "caller
  verification needs P3 authenticators").
- **End user.** Must enrol a TOTP once if they have no mail or mobile number held in AD/HR. Rare
  and one-off, so the page must be short and safe, not pretty.
- **Security.** ManageEngine's own OTP was brute-forced: CVE-2022-36413, CVSS 9.1, OTP brute force
  leading to password reset, fixed 2023-03-03
  ([customer-voice §4.1](../../business/market-research/manageengine-ad-customer-voice-and-security.md),
  [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-36413)). Every number below exists to close
  that class.

## 2. Parity baseline

| ID | ME capability | Our v1 coverage |
| --- | --- | --- |
| ADM-142 | Console 2FA: email OTP, SMS, authenticator apps; per-technician skip ([matrix](../../business/competitive-analysis/feature-parity-matrix.csv)) | Technician console MFA is a separate spec (T-0121). This spec supplies the shared OTP/TOTP rules (§4–§5) so both use one implementation. No per-technician skip (matrix verdict: MFA mandatory for every admin). |
| ADM-136 | Help-desk reset console: reset, must-change flag, unlock in one pop-up | Reset and unlock stay in the console; this spec adds the verification step (§4). |

ManageEngine's OTP length, lifetime and attempt limits are **not in our research**. The numbers
below are our own, set from the threat model and standards, not copied from ME. A research ticket
asks `market-analyst` for ME's values so the battlecard can state them (§10).

## 3. Enhancements (all v1)

1. **Caller verification inside reset/unlock** (ENH-09 itself), audited in the reset event.
   Pain: CVE-2022-36413 and the vishing vector above.
2. **Cooling-off for new factors** (new; §5): a freshly enrolled TOTP cannot verify a caller for
   24 hours. Pain: TM-TB1-T13, an attacker with the password enrols first.
3. **Technician sees which factor, how old** (§3): the console shows the factor used and a
   badge when it was enrolled less than 7 days ago.

## 4. OTP rules (email and SMS codes)

Delivered to the caller; the technician types in what the caller reads back.

| # | Rule | Value | Test |
| --- | --- | --- | --- |
| 4.1 | Length, alphabet | **6 digits**, uniformly random from a CSPRNG, leading zeros kept | Statistical test over 100k codes; digits only |
| 4.2 | Lifetime | **5 minutes** (300 s) from issue; checked server-side with the server clock | A code is refused at 301 s and accepted at 299 s |
| 4.3 | Attempts per code | **3** wrong entries; the 3rd wrong entry puts the challenge in `failed` and the code is dead even if correct afterwards | 3 wrong then correct → refused |
| 4.4 | Single use | A correct entry consumes it; the same code never verifies a second time, for any target or operation | Replay of a consumed code → refused |
| 4.5 | One open challenge per target | Issuing a new challenge for the same target moves the previous open one to `cancelled` | Old code refused after re-issue |
| 4.6 | Issue rate per target | **3 challenges per target per rolling hour**, across all technicians. The 4th is refused with a reason shown to the technician; no AD change happens. At most 9 guesses per hour per target (4.8) | 4th issue → refused |
| 4.7 | Issue rate per technician | **10 challenges per technician per rolling hour**; **5 `failed` challenges per technician per hour** → technician's verification is paused for 15 min and an alert goes (EP-9) to every holder of the permission `authenticator.reset` and every `tenant-owner` | Boundary tests at 5 and 6 |
| 4.8 | Guess probability | Email/SMS OTP: 3 attempts × 3 issues per target-hour (4.6) = 9 guesses against 10⁶ codes → **9×10⁻⁶ per target-hour**. TOTP (§5): 3 valid codes in the ±1 window × 10 wrong entries per enrolment-hour = 30 guesses against 10⁶ → **3×10⁻⁵ per enrolment-hour**. Stated side by side so security can challenge both. | Arithmetic in the spec; limits tested by 4.3, 4.6 and AC-TOTP-2 |
| 4.9 | Enforcement | **Server-side only**, in PostgreSQL, shared by all nodes. No client-side counter, no limit keyed on client-reported IP (TM-TB11-T5) | Two nodes, parallel guesses: total still ≤ 3 |
| 4.10 | Storage | Only `code_mac`, a keyed MAC under a key derived from the tenant data key (DM-38.I2). The code never appears in logs, audit, API responses or the technician's screen | Grep logs and DB in test |
| 4.11 | Comparison | Constant-time | Code review item, not a Given/When/Then |
| 4.12 | Channels | **Email** and **SMS** to a destination read live from AD or HR at issue time (DM-38.I1, DM-37.I2). **SMS appears only when a gateway is configured** (EP-9); if only email is available, only email is offered. Voice call, in-app push and "send to another number" do not exist in v1 | No UI path to type a destination |
| 4.13 | Destination hygiene | A destination whose attribute was changed in the last 24 hours is not used (an attacker with AD write access could otherwise point the code at themselves). If AD replication metadata cannot give the change time for that attribute, the engineer reports it and the rule falls back to a tenant-wide setting, not silent skip (§11 Q1) | Edit `mail`, issue within 24 h → destination refused |
| 4.14 | Masking | The technician sees a masked destination (`j***@example.com`, `+•• ••• ••• 4821`) never the whole address | UI test |
| 4.15 | Target | Technician ≠ target user. Verification authorises exactly one operation: the reset/unlock on that target (DM-38.I3) | Technician verifies self → refused |
| 4.16 | Verified window | After a correct code, the reset/unlock must run within **5 minutes**; used once. The unlock-plus-reset in one pop-up counts as one operation | 301 s after verify → needs a new challenge |
| 4.17 | Delivery failure | If email/SMS transport rejects the message, the challenge is `cancelled` with a reason, does not count towards 4.6, and the technician is told delivery failed. No code is shown on screen as a fallback | Break SMTP → no code on screen |
| 4.18 | Enumeration | An unknown, disabled, out-of-scope or no-destination target gets one generic "cannot verify this caller" state in the API; the console shows the reason only to a technician whose scope already includes the target (TM-TB11-T1 class) | Same API body for the four cases |

## 5. TOTP rules

- **Parameters.** RFC 6238 TOTP, **HMAC-SHA-1, 6 digits, 30-second step**, the common
  interoperable setting for Microsoft/Google Authenticator and others
  ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)). Fixed in v1; not configurable.
- **Window.** Accept the current step and **one step either side** (±30 s). Nothing wider.
- **Replay.** A time step already used for that enrolment is refused (`last_used_step`), so a
  shoulder-surfed code works at most once.
- **Attempts.** **5 wrong entries** per pending verification, then the verification is `failed`;
  **10 wrong entries per rolling hour per enrolment** pauses the factor for verification for 1
  hour. The pause is not a lockout of AD; it only closes the verification path (a technician is told
  to use another factor).
- **Seed.** 160-bit CSPRNG secret, base32; sealed at rest, shown once in the enrolment page (QR
  and typed form), never returned afterwards (DM-37.I1).
- **Cooling-off.** A new TOTP enrolment cannot satisfy caller verification until **24 hours after
  the notification of §6.5 was accepted by the mail transport**. Email/SMS OTP stays available
  meanwhile. During cooling-off the factor is `active` for re-enrolment checks but listed as
  "cooling-off" to the technician (§3 item 3 badge).

## 6. The enrolment page (AN-5)

**Who and where.** An end user, on a hostname bound to the `totp-enrolment` capability (DM-04).
Not on the console hostname; refused on the break-glass hostname (AN-8). The page is **off until
a tenant-owner binds a hostname and turns it on**, and not offered while the mail transport is not
configured (§6.5 depends on it).

**Users in scope.** Enabled AD users of a connected on-prem AD, whose account is able to
authenticate (not disabled, not expired, password not set to "must change at next logon" — for
that they use Windows first). Cloud-only Entra users have no AD plane to prove themselves in and
are out of scope for v1 (matrix in §7).

### 6.1 Own AD authentication — required

- **Given** a visitor on the enrolment hostname, **When** they open the page, **Then** they see
  only a sign-in step; no enrolment control is rendered and the enrolment operation answers `401`
  without a valid authentication record.
- Authentication is one of: **SPNEGO/Kerberos** from a domain-joined browser, or **username +
  password through the connector's `VerifyUser`**. Never an LDAP bind from our server, never a
  password stored (ADR-0002 rule 3). AN-9 (`GET /auth/negotiate`) is never served on an AN-5
  hostname (TM §7.6), so AN-5 **carries its own Negotiate exchange**: an AN-5 route (HTTP Negotiate,
  [RFC 4559](https://www.rfc-editor.org/rfc/rfc4559)) that hands the AP-REQ to the connector's SPNEGO
  acceptor — the same acceptor, a separate route. Kerberos only; an NTLM-only token gets the generic
  failure. The route is a new row in the `policy.yaml` anonymous allow-list under AN-5 and is
  reviewed under RT-7 (§8).
- Success yields a **pending enrolment** only: server-side record, CSPRNG handle of ≥128 bits
  stored hashed, bound to the user's GUID and connection, in an `HttpOnly`, `Secure`,
  `SameSite=Strict`, `__Host-` cookie; lives **10 minutes** (deviation, below), allows **5 code confirmations**,
  consumed on success or expiry. **Deliberate deviation:** TM §7.6 rule 1 gives a pending sign-in 5
  minutes; here it is **10**, because a user may need to install an authenticator app after
  authenticating. The 5-confirmation cap and every other property of rule 1 are kept. For
  `security-architect` to accept or cut to 5 (§8).
- Password failures use the **same per-account counter and refusal as TM-TB1-T9**; this spec adds
  no separate numbers. It stops below the domain lockout threshold.
- Responses for unknown account, wrong password, disabled account and throttled account have the
  same body, status and timing class (TM-TB11-T1).
- A visitor cannot enrol for any account except the one they authenticated as; the user ID is
  never taken from the request body.

### 6.1a Classification under ADR-0005

- **End-user enrolment and re-enrolment on AN-5 (6.2, 6.3)** is **system bookkeeping** under ADR-0005
  rule 10 ("own factor enrolment, DM-37 self-service"), not an Action: it writes only our own
  authentication store, for the person who just proved themselves in the AD plane. The audit actor
  is a **directory-user principal** (connection + GUID), not a console user. `solution-architect`
  amends the bookkeeping list and the DM principal kinds (§9).
- **Technician-verified reset (6.4)** is an administrator change to a security factor, so it **is an
  Action**: `x-permission: authenticator.reset`, `Target: Store`, run by the operation pipeline with
  preview, gate and audit. **Step-up: yes** — it removes a security factor, so it is on the TM §7.4
  step-up list (to be added there by `security-architect`); reversibility class `Irreversible`
  (the seed cannot be restored; the user enrols anew).

### 6.2 First enrolment

1. The user authenticates (6.1).
2. The page shows a QR code and the typed secret. It also offers the authenticator names we have
   tested with (Microsoft Authenticator, Google Authenticator).
3. The user types the current 6-digit code; on success the enrolment becomes `active`.
4. The page shows a short confirmation and tells the user that a notice was sent.

Goal: **≤ 4 screens and ≤ 60 seconds** from opening the hostname to done for a user who already has
an authenticator app (target to confirm with `product-designer`). There is no ManageEngine baseline
in our research; ADSSP's enrolment is described as a coercive popup that blocks the desktop (ADSS
W15 in
[the ADSSP research](../../business/market-research/manageengine-adselfservice-plus.md)); ours is a
page the user chooses to open.

### 6.3 Re-enrolment (replace an existing TOTP)

An `active` TOTP exists for the user. A new enrolment is accepted only when:

- (a) the user passes 6.1 **and** enters a valid code from the existing factor (cooling-off or not);
  the old factor is revoked when the new one is confirmed; or
- (b) a **technician-verified reset** (6.4) revoked the old factor first.

If neither holds, the page says the user must contact the help desk, and no seed is created. A
user with a pending (unconfirmed) enrolment simply restarts; the previous pending one is discarded.

### 6.4 Technician-verified reset of an enrolment

- Needs a distinct permission (`authenticator.reset`), granted through tenant role data to whoever the tenant chooses (no built-in help-desk role exists, DM-34).
- The technician must first verify the caller with an **email/SMS OTP (§4)**, never with the TOTP
  being reset. A target with no held destination cannot be reset by the help desk; the console
  says why. (A tenant-owner can use the tenant-owner reset in DM-37.I4 for console accounts; that
  does not extend to end users.)
- Effect: the enrolment moves to `revoked` and the user may enrol fresh at 6.2 after 6.1. The
  reset is itself audited and notified (6.7).

### 6.5 Notification

On every successful enrolment, re-enrolment and reset:

- Sent to **contact data already held before the event** (mail and mobile read live from AD/HR);
  never to anything typed in the page or changed in the last 24 hours (rule 4.13).
- Content: what happened (enrolled / replaced / reset), UTC time, source address as seen by the
  server (advisory), and "if this was not you, call the help desk now". No code, no seed, no link
  that acts. 
- If there is **no held destination**, enrolment is refused with the generic message "contact your
  help desk" and is counted in a coverage report ("users with no contact data"). 
- If the transport accepts the message, the cooling-off timer starts (§5). If it fails, the
  enrolment stays but cooling-off does not start, delivery is retried every 15 minutes for up to
  24 hours (`notice_state` = `failed` while retrying), and a `notice.failed` event is audited and
  alerts every `tenant-owner` on the first failure. **End state:** if all retries fail,
  `notice_state` = `abandoned`; the enrolment stays `active` but **never usable for caller
  verification** (cooling-off never starts), a health finding "TOTP enrolment without delivered
  notice" is raised for the tenant-owner, and `notice.abandoned` is audited. It becomes usable only
  if a later notice is delivered (a tenant-owner may trigger "resend notice" after fixing the mail
  transport or the user's contact data); the user can also revoke it by re-enrolling (6.3a).

### 6.6 Audit

Each of these is an audit event (ADR-0005 audit trail, hash-chained), recording actor type
`end_user` (or the technician), target GUID, connection, method, source address, and never a code
or seed: `authenticator.enrol.started`, `.confirmed`, `.failed` (reason), `.refused` (reason),
`.replaced`, `.reset` (with technician and verification factor), `.notice.sent`, `.notice.failed`,
`callerverification.issued` / `.verified` / `.failed` / `.expired` / `.cancelled`. The reset audit
event carries the verification factor, the factor's age and the challenge ID (DM-38.I4).

## 7. Platform matrix

| Platform | Email/SMS OTP caller verification | TOTP enrolment page | Notes |
| --- | --- | --- | --- |
| On-prem AD, any supported functional level | Yes | Yes | Needs `mail`/`mobile` readable by our connector identity (no new write right). No DC-side component. |
| Windows Server 2016, 2019, 2022, 2025 DCs | Yes | Yes | No DC code, no DC dependency. SPNEGO needs the `HTTP/` SPN registered by an admin (TM §7.6 rule 5). |
| Samba AD (lab) | Yes | `VerifyUser` yes; SPNEGO `[UNVERIFIED — lab]` | Per TM §7.6 rule 5 |
| Entra ID, hybrid user (has AD account) | Yes, with AD/HR contact data | Yes | AD plane proves identity |
| Entra ID, cloud-only user | **No in v1** | **No in v1** | No AD plane to authenticate the user; Entra authentication methods are never read as a factor (DM-37.I4). Cloud-only is an M4 SSPR question. |
| Multi-forest | Yes, per connection | Yes, one enrolment per (connection, GUID) | The hostname maps to a tenant; the user picks the forest only if more than one accepts the account. |
| Self-hosted / SaaS-ready | Yes | Yes | Page reachable only on the bound hostname; SaaS needs the customer's front door (TM-TB11-T6). |

## 8. Security and audit

- **Privileges.** Directory read of `mail`, `mobile` and `whenChanged` metadata. No write. No new
  right beyond the connector's read scope. Console role grants: verify caller (technician),
  `authenticator.reset` (granted by tenant role data, e.g. to a help-desk lead; only `tenant-owner` is built in, DM-34).
- **For `security-architect`.** (1) the cooling-off and destination-hygiene rules against
  TM-TB1-T13; (2) the AN-5 anonymous surface against TM §7.6 and RT-7: the enrolment operations **and the AN-5
  Negotiate route** (6.1) are listed in `policy.yaml`; the 10-minute pending lifetime deviation;
  step-up for the reset Action; (3) timing equality for 6.1 and 4.18; (4) the 24 h rule's dependence
  on replication metadata; (5) residual risk: an attacker who has the password **and** controls
  the user's mailbox can still enrol; the notice only helps if the mailbox is not theirs.
- **Residual: insider DoS.** The per-target cap (4.6) lets any technician in scope use up a target's
  3 challenges per hour and so block verification of that user for up to an hour. Accepted for v1
  (the audit names the technician; 4.7 alerts on abuse); the alternative, per-technician sub-caps,
  would raise the guess count.
- **Residual from the threat model.** An attacker with the user's password can enrol first; the
  notice and cooling-off shorten the window (TM-TB1-T13).

## 9. Domain-model changes for `solution-architect` (DM-37, DM-38)

No directional question remains. Apply to
[domain-model.md](../../development/domain/domain-model.md):

**DM-37 AuthenticatorEnrollment**
- Add attributes: `cooling_off_until` · `notice_state` (see below) ·
  `last_used_step` · `failed_attempts` · `paused_until` · `replaces` (previous enrollment ID,
  nullable) · `expires_at` (pending only, 10 min) · `confirm_attempts` (pending only, max 5).
- Add I5: one `active` TOTP per subject (connection+GUID). Confirming a new one revokes the old.
- Add I6: an end-user TOTP is created only after the subject's own AD authentication in the same
  ceremony (`authority_anchor` = `ad_plane`, never `owner_approval` for end users). Replacement
  needs the existing factor (§6.3a); otherwise a revoke through §6.4.
- Add I7: a TOTP enrollment cannot satisfy DM-38 before `cooling_off_until`.
- Add I8: every enrol, replace and reset writes the audit events of §6.6 and a notice (§6.5).
- `notice_state` enum is `pending`, `sent`, `failed` (retrying), `abandoned` (§6.5).
- Add I9: an `active` enrolment with `notice_state` ≠ `sent` cannot satisfy DM-38.
- Principal kind: add a **directory-user principal** (connection + GUID) as audit actor for AN-5
  self-service; amend ADR-0005 rule 10's bookkeeping list with "own factor enrolment (DM-37
  self-service)" (§6.1a).
- Extend lifecycle: `pending → active → revoked`; `pending → expired` (10 min).
- I3's authority-factor wording stays for `webauthn` console accounts; add that I6 above is its
  end-user analogue so the two are not confused.

**DM-38 CallerVerification**
- Extend the existing `factor` enum to `email_otp` | `sms_otp` | `totp` (matching DM-37 method
  names). No `channel` attribute. Length (6) and max attempts (3) are fixed constants of the rule set
  (§4), not stored per row.
- Add attributes: `delivered_at` · `verified_at` · `authorised_until` (verified_at + 5 min) ·
  `factor_enrolled_at` (TOTP only; for the age badge).
- Add I5: at most one open challenge per target; a new issue cancels the old.
- Add I6: rate limits §4.6, §4.7 and attempt limits §4.3 are enforced in the database, not in
  memory.
- Add I7: technician ≠ target.
- Add I8: destination not changed in the last 24 h (or tenant fallback if metadata is missing).
- Add I9: TOTP `factor` rejected during cooling-off.
- Lifecycle: `issued → verified | failed | expired | cancelled`, and `verified → consumed` when
  the Action runs, or `verified → expired` when `authorised_until` passes.

## 10. Acceptance criteria

Each is verified by `qa-verifier` via UI or API with evidence (screenshot, response body, audit
row). IDs are for traceability.

**OTP**
1. **AC-OTP-1** Given a target with a held email, When a technician issues a code, Then a 6-digit
   numeric code is delivered, expires after 300 s, and the technician's screen shows only the masked
   destination.
2. **AC-OTP-2** Given an issued code at 299 s and another at 301 s, When each is entered correctly,
   Then the first verifies and the second is refused.
3. **AC-OTP-3** Given a code, When 2 wrong then the correct code are entered, Then it verifies; when
   3 wrong then the correct code are entered, Then it is refused and the challenge is `failed`.
4. **AC-OTP-4** Given a verified code, When it is entered again, Then it is refused.
5. **AC-OTP-5** Given 3 challenges for the same target in an hour, When a 4th is issued by any
   technician, Then it is refused and no message is sent.
6. **AC-OTP-6** Given two nodes handle guesses for one challenge in parallel, When 10 wrong codes
   are sent, Then at most 3 are counted as attempts and the rest are refused without evaluating the code.
7. **AC-OTP-7** Given a technician reaches 5 failed challenges in an hour, Then further issues are
   refused for 15 minutes and every holder of `authenticator.reset` and every `tenant-owner` is alerted (EP-9).
8. **AC-OTP-8** Given a target's `mail` attribute was edited 2 hours ago, When a code is requested,
   Then that address is not used (or the tenant fallback applies, §11 Q1) and the technician sees
   why.
9. **AC-OTP-9** Given no SMS gateway, When a technician opens verification, Then SMS is not offered;
   no control for typing a destination exists anywhere.
10. **AC-OTP-10** Given a transport failure, When the code is requested, Then the challenge is
    `cancelled`, no code is shown, and the attempt does not count towards the hourly cap.
11. **AC-OTP-11** Given a technician who selects themselves as target, Then verification is refused.
12. **AC-OTP-12** Given an unknown, a disabled, an out-of-scope and a no-destination target, When
    verification is requested through the API, Then body and status are identical and the timing
    class is the same.
13. **AC-OTP-13** Given a verified challenge, When the reset runs within 5 minutes, Then one audit
    event records technician, target, factor, masked destination, challenge ID and factor age; When
    run at 301 s, Then it is refused and a new challenge is needed.
14. **AC-OTP-14** Given any test run, When logs, DB rows and audit are searched for the code,
    Then it is found nowhere in clear.

**TOTP and enrolment (TM-TB1-T13)**
15. **AC-ENR-1** Given an unauthenticated visitor on the enrolment hostname, When they call the
    enrolment operation directly, Then the response is `401` and no seed is created.
16. **AC-ENR-2** Given a user, When they authenticate by SPNEGO (Kerberos) or by `VerifyUser`,
    Then a pending enrolment bound to that user exists, expiring in 10 minutes; a Negotiate token
    that offers only NTLM gets the generic failure.
17. **AC-ENR-3** Given user A authenticated, When the request names user B's GUID, Then it is
    refused and an `enrol.refused` event is audited.
18. **AC-ENR-4** Given wrong passwords on the page, Then the response is identical for unknown,
    wrong-password and disabled accounts, and the per-account counter stops below the domain
    lockout threshold (Samba lab with threshold 5).
19. **AC-ENR-5** Given a first enrolment, When the user types the current code, Then the factor is
    `active`, the seed is never shown again (API and UI), and 5 wrong confirmations expire the
    pending enrolment.
20. **AC-ENR-6** Given an active TOTP, When the user authenticates but cannot give the current
    code, Then no new seed is created and the page says to contact the help desk. When they give it,
    the new factor replaces the old one.
21. **AC-ENR-7** Given a technician-verified reset using the TOTP being reset, Then it is refused;
    using an email OTP, Then the enrolment is `revoked`, an audit event names the technician and
    factor, and a notice is sent.
22. **AC-ENR-8** Given a successful enrolment, Then a notice goes to the mail and mobile already
    held (not to anything entered on the page), containing time, action and no code, seed or link.
23. **AC-ENR-9** Given a user with no held contact data, When they try to enrol, Then it is refused
    with the generic message and counted in the coverage report.
24. **AC-ENR-10** Given a notice the transport rejected, Then the enrolment stays active, cooling-off
    has not started, a retry runs every 15 min, and `tenant-owner`s are alerted; When all retries over
    24 hours fail, Then `notice_state` is `abandoned`, the factor is refused for caller verification,
    a health finding exists and `notice.abandoned` is audited.
25. **AC-ENR-11** Given a TOTP enrolled 23 hours after notice acceptance, When a technician tries to
    use it for caller verification, Then it is refused and email/SMS are offered; at 25 hours it is
    accepted and the badge says "enrolled < 7 days ago".
25a. **AC-ENR-12** Given a confirmed first enrolment, When it completes, Then the audit chain
    contains `authenticator.enrol.confirmed` and `authenticator.notice.sent` (or `.notice.failed`),
    each with actor (directory-user principal), target GUID, connection, method `totp` and source
    address, and no code or seed in any field. Given a confirmed replacement, Then
    `authenticator.replaced` (carrying the previous enrolment ID) and the notice event are present
    likewise; Given a technician reset, Then `authenticator.reset` names the technician, verification
    factor and challenge ID.
26. **AC-TOTP-1** Given a code from the previous, current or next 30-s step, Then it is accepted;
    from two steps away, Then refused; the same step used twice, Then refused the second time.
27. **AC-TOTP-2** Given 10 wrong entries in an hour, Then the factor is paused for verification for
    1 hour without any change in AD.

**Empty, error, partial and scale**
28. **AC-SCALE-1** Given a directory of 100k users and groups with >1,500 members, When a challenge
    is issued, Then the target lookup uses an indexed key (GUID), group size is irrelevant, and the
    issue operation meets its budget (target p95 ≤ 3 s excluding provider delivery; to be confirmed
    against engineering-standards §7).
29. **AC-EMPTY-1** Given the enrolment page is not switched on, or the mail transport is
    unconfigured, Then the hostname shows a neutral "not available" page and the console states what
    is missing to the tenant-owner.
30. **AC-PART-1** Given the connector is offline, Then both the page and caller verification fail
    closed with a generic message; no verification can be authorised from cache.

## 11. Out of scope and open questions

**Out of scope.** Push, passkey/WebAuthn for end users, security questions, SSPR (M4); voice OTP;
enrolling someone else's factor; cloud-only Entra users; TOTP algorithms other than SHA-1/6/30;
HR-sourced contact data beyond what ENH-03 already provides; "trust this browser".

**Open questions (none directional).**
- **Q1** Does AD give us the change time of `mail`/`mobile` per attribute (replication metadata
  `msDS-ReplAttributeMetaData`) at acceptable cost? Owner: `ad-expert` + `directory-engineer`,
  answered before the build. If not, the tenant-wide fallback is: contact attributes edited
  after the last sync are treated as unverified for 24 h. Not a CEO question.
- **Q2** `product-designer` confirms the ≤3-interaction target for reset-with-verification (the
  blueprint's §ADM-136 target) and the ≤4-screen enrolment page.
- **Q3 (answered).** [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)
  §3.1.3.2 (out-of-band): invalid unless completed within **10 minutes**; at least six decimal
  digits; accepted **only once**; a secret under 64 bits needs rate limiting, and generating a new
  secret **does not reset the failed count**. §3.1.4.2/3.1.5.2 (OTP): accepted once while valid.
  §3.2.2: upper bound of 100 consecutive failures; lower limits allowed. Our values (5 min, 3
  attempts, 6 digits, single use) are inside every limit. **Gap this exposes:** NIST says re-issuing
  must not reset the failed count; our 4.5 cancels the old challenge, but 4.6/4.7 cap total guesses
  per target-hour at 9, which satisfies it. 4.6 is therefore a requirement, not tuning.

**Follow-up work.** Research ticket for ME's OTP length, validity and attempt limits (post
CVE-2022-36413 fix) for `market-analyst`.
