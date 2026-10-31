---
name: ceo-action-handover
description: When a CEO decision needs account or credential handover, build the handover tooling first; an action marked done with no note is not evidence
metadata:
  type: feedback
---

When a decision's answer needs the CEO to hand over access (tenant, lab, accounts), don't re-queue the blocked
worker just because the action is marked `done`. A-0001 was done with no note and there was no handover path.
Cut a devops ticket that builds a one-command bootstrap: interactive sign-in, a cert-based app or service credential,
written to a gitignored 0600 file. Make that ticket file the CEO's one-step action and gate the blocked tickets on it.

**Why:** the CEO should never paste a password, and a worker relaunched without credentials just blocks again
(D-0001 / T-0183, 2026-10-23).

**How to apply:** for any "CEO provides X" decision, set the blocked tickets' depends_on to the harness ticket, not to
the action. Related: [[triage-blocked-on-another-ticket]], [[triage-env-blockers]].
