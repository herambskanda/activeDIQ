---
title: Password-filter fail mode, fail-open or fail-closed — decision prep
date: 2026-11-05
updated: 2026-11-05
status: draft
owner: security-architect
kind: decision-prep
ticket: T-0146
refs: TM-TB12-T6, TM-Q20, TM-R7, TM-D14, ADR-0007, agent-host-addc-contract C16, TM §16.2
---

# Password-filter fail mode: fail-open or fail-closed

Obligation: threat model §16.2 ("Customer-affecting risk acceptance") and TM-Q20. The M4 password-filter build
(T-0145) cannot start until this is decided (TM-TB12-T6). The question for the CEO, in business terms:
**if our password check on a domain controller cannot run, do we let the password change through anyway, or refuse it?**

## 1. What "cannot run" actually means

The filter (`native/passfilt`, in LSASS) checks a signed, locally cached policy and breach list, with no network I/O
in the call path (TM §12; FEAS §2.3). The server being down or the network being cut therefore does **not** stop the
check, and an installed policy stays in force however long the agent is offline (ADR-0007 §3, which deliberately avoids
creating a second fail-mode decision). The cases left are narrow:

| Case | Likelihood | Fail-open outcome | Fail-closed outcome |
| --- | --- | --- | --- |
| F1. Filter installed, no policy ever applied (first minutes after install, failed first sync) | Common at rollout | Native rules only | **Every password change on that DC refused** |
| F2. Policy or breach-list file corrupt, unreadable or fails signature check | Rare | Native rules only | Refused until repaired |
| F3. Evaluator error or deadline exceeded (bounded-time rule) | Very rare (fuzzed, fault-injected, T-0145) | Native rules only | Refused for that request |
| F4. Agent stopped or pipe unavailable | Common (restart, update), but only matters if the filter needs the pipe; the *notification* half feeds password sync, not the check | Change allowed, sync event queued | Same, unless the design makes the pipe mandatory (it should not) |
| F5. DLL fails to load at all (bad signature under LSA protection, wrong build) | Rollout/update mistake | Windows skips it, **no choice of ours**: effectively open `[UNVERIFIED: Microsoft docs reviewed do not state the load-failure behaviour; lab test needed in T-0145]` | Same, we are not running |

Two facts frame the whole decision:

1. **Open does not mean "no password policy".** Our filter is additive. Windows' own length, complexity, history and
   fine-grained policy still apply to every change ([installing a filter](https://learn.microsoft.com/en-us/windows/win32/secmgmt/installing-and-registering-a-password-filter-dll)).
   Fail-open means "the extra banned-list, breach-list and custom rules are skipped for that change".
2. **Filters must be on every DC.** Filtering happens only on the machine holding the account, and all DCs are writable
   ([programming considerations](https://learn.microsoft.com/en-us/windows/win32/secmgmt/password-filter-programming-considerations)).
   A DC without our filter is already "open". Fail-closed on one DC only shifts the user's change to
   another DC when the client retries; it does not give a hard guarantee unless every DC runs it.

## 2. Options

### A. Fail-open (change allowed, loud signal)

- **Customer impact.** No outage: help desks and users never hit a refusal caused by our product. A weak or breached
  password can be accepted during F1–F3 windows. Exposure is bounded by native policy and by how soon the alert is acted on.
- **Attacker view.** Needs SYSTEM on the DC to stop the filter, and then already owns the domain. No new path for
  a lower-tier attacker; a *compromised activeDIQ server* cannot create one either (policy is data within bounds, TM-D14).
- **Competitive.** ManageEngine's Password Sync Agent on every DC enforces its policy on native changes
  ([ADSS-101, ADSS-108](../../business/market-research/manageengine-adselfservice-plus.md)). Its failure mode is
  `[UNVERIFIED]` in our research, so we cannot claim parity or superiority on this point.
- **Compliance.** Hard to describe as "enforced" in an audit where a control may silently lapse; the audit trail (below) is what answers that.

### B. Fail-closed (change refused)

- **Customer impact.** Guaranteed enforcement, but any fault in our product blocks password changes on that DC for
  **everyone**, including an incident-response reset of a compromised account, a leaver's reset, or an expired-password
  logon at the start of the working day. The incident case is the worst: the product meant to help the defender stops
  the defender. This also makes a bad rollout (F1, F5-like mistakes) a business-hours outage on a Tier-0 system, which is
  the story buyers already tell about ManageEngine agents ([ME-SEC](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
- **Attacker view.** Gives a denial-of-service lever: anyone who can corrupt the cached policy file, or make a signature
  check fail, or (via a malicious signed policy, TM-R7) can freeze password changes forest-wide. Closed raises the value
  of attacking the policy path.
- **Compliance.** Cleanest sentence for a regulated buyer: "no password is accepted unchecked".

### C. Per-install setting, local to the DC, default open (recommended)

Fail-open by default. Customers who need strict enforcement set **fail-closed** per DC, with these rules:

1. **Local, not pushed.** The mode is an installer/registry value on the DC (MSI property, changed only by a local administrator and audited).
   It is **not a field in agent policy**; the host contract already has no such setting (agent-host-addc-contract C16, fitness R2).
   A compromised server therefore cannot flip every DC to refuse changes.
2. **Armed only after first good policy.** Closed mode refuses nothing until a policy has been applied and verified once, so a fresh install or failed first sync cannot lock a DC (removes F1).
3. **Closed refuses only on F2/F3**, never because the pipe or server is unreachable (F4 is never a refusal).
4. **Refusal is explainable.** The user-visible failure is the standard "does not meet policy" path, with a distinct Windows event ID on the DC and an alert in the console naming the cause.
5. **Break-glass.** Setting the value back to open takes effect without a reboot `[UNVERIFIED: confirm in T-0145 that the value is read per call]`.

Cost: two code paths to test, and documentation. Both are inside the T-0145 fault-injection plan.

## 3. Signal required under any option

A silent open is the real risk, so each option needs the same tripwires (these are not CEO decisions):

- Every "check skipped" or "change refused" writes a DC Application-log event and an agent event to the server audit trail (attributable and exportable, as for every change we make).
- Console health shows per-DC filter state: `enforcing`, `not armed`, `degraded (open)`, `degraded (closed)`.
- Alert after N skipped checks in a window (N set at build time).
- Fitness function for the ADR that follows: fault-injection test in CI/Windows lab for F2, F3 and F5 asserting the configured mode and the event; a lint/R2 check that no policy field named like a fail mode exists.

## 4. Summary for the CEO

| | A. Open | B. Closed | C. Local setting, default open |
| --- | --- | --- | --- |
| Fault in our product stops password changes | No | **Yes** | Only where the customer chose closed |
| Weak password slips through during a fault | Possible, native rules still apply | No | Possible by default |
| Server compromise can freeze password changes | No | Possible if mode is pushed | No (mode is local) |
| Sells to regulated buyers | Weaker | Strongest | Both |
| Build and test cost | Lowest | Low | Moderate |

**Recommendation: C.** Default open with loud signalling, strict mode available as a local per-DC choice. A fault in a
Tier-0 product should not be able to stop the domain's password changes by default, and the worst case of open (a weak
password under native policy during a rare, alerted fault) is smaller than the worst case of closed (no emergency
resets, plus a new outage lever). Confidence: medium; the weak point is that we have no data on the customers'
appetite, which is exactly why it is a CEO question.

## 5. What the CEO is asked (one question, business terms)

> When our password check on a domain controller cannot run, should a password change be **allowed** (and flagged to
> the administrator) or **refused**? Recommended: allowed by default, with a per-DC "strict" switch that
> security-conscious customers can turn on.

Answers and what follows: **allow** → ADR for open, local strict option deferred; **refuse** → ADR for closed with the
armed-after-first-policy rule still mandatory; **recommended** → ADR for C, fitness function as in §3.

## 6. Open items / not verified

- F5 load-failure behaviour and per-call reading of the mode value: lab tests in T-0145.
- ManageEngine agent's failure mode: not in our research; ask `market-analyst` if the CEO wants a comparison line.
- No customer evidence on preference yet; the partner discovery questionnaire could carry the question.
