---
name: tier0-verify-lessons
description: VerifyConnection stream traps — connector must set DM-24.I4 fingerprint, duplicate fingerprints refuse the run, lab Tier-0 test recipe
metadata:
  type: project
---

- `RightsFinding.fingerprint` was never set by the connector (comment in entra.go claimed the stream did) — the server's mapFinding rejects every real finding ("verify stream violates the contract: finding"). Now set in `adCheck.add` via `rights.Fingerprint`. Unit fakes passed because tests built findings with `fp(n)` by hand.
- The server also refuses a repeated fingerprint per run. Several ACEs for one trustee/mask on one Tier-0 object collapse to one exposure (deduped in `add`, EXCESSIVE + tier0-membership only). MISSING findings still collide (T-0842).
- Don't reason about "dup" from a global debug set: reset per stream, the lab test runs VerifyAD several times.
- Lab Tier-0 test: `labadmin.AddMember(groupDN, sam)` (auto-removes on cleanup). Boot with svc in Domain Admins -> "verdict refused; V7=fail ... over_privileged" (not a Tier-0 503: the connection never activates). The 503 Tier-0 reason is reached by activating clean, adding the account, `svc.Verify(KindManual)`, then GET.
**Why:** QA rejected T-0669 AC2 for exactly this. **How to apply:** any new finding path must be run through a real VerifyAD in the lab, not hand-built findings.
