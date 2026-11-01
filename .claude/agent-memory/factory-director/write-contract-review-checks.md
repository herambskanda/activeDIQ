---
name: write-contract-review-checks
description: Connector write-contract review — per-target context vs per-touched-set checks; live re-read must cover every tier0 basis or declare a residual; Entra credential coverage
metadata:
  type: feedback
---

When a write contract checks the whole touched set but the server context it reads is keyed to the target only, the check cannot be met for the other touched objects. Demand a repeated, per-object context, and make a missing entry fail closed.

**Why:** T-0091 (2026-10-22). The contract had a single CorrelationStatement bound to the target, yet step 6 checked "the rest of the touched set against the context". Both I and the security-architect consult caught it. Rejected together with two more majors.

**How to apply:**
- For each check step, name the field that feeds it, per object.
- A live re-read before a write must list, per tier0 basis (C1–C16, E1–E5), what is re-read. Otherwise the stale-set window is an explicit residual.
- Entra identity hygiene covers keyCredentials AND passwordCredentials, on the app AND the SP. Never `hint` or `secretText`.
- Freshness timestamps defend only against an honest-but-stale server. Say so.
- Spec flow has no security stage: consult security-architect in the background at the start, and do the CI checks meanwhile.

Related: [[derived-state-retention-pins]], [[pipeline-adr-review-checks]]

- 2026-10-22 (T-0122): for detective controls (post-write re-read, shrink logs, baselines), ask "what if the read/write itself fails?" — unspecified failure = attacker suppresses the alert. Limits the TM says "never raise" must be build-time constants, with a case proving no knob exists.
- 2026-10-22 (T-0129): when a new fail-closed rule says that an unknown read is tier0 and takes precedence, check it against every existing retry/fallback path (rule 5 verify window, DC fallback). Otherwise the older reason (dc_unavailable) can never be reached and every outage becomes an unmutable critical alert.
