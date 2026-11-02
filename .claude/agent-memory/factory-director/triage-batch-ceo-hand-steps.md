---
name: triage-batch-ceo-hand-steps
description: When several open CEO actions share one hand-step (e.g. Proxmox VM builds), file one scoped-authorisation decision instead of re-noting each blocked ticket
metadata:
  type: feedback
---

When three or more open CEO actions need the same kind of hand-step (T-1321: A-0023, A-0028 and A-0031 were all Proxmox VM builds, 1 to 5 days old, gating 6 tickets including P1 T-0413), stop re-noting "waits on A-…" every triage. File one directional decision that offers a scoped worker authorisation (D-0022: a pool-scoped Proxmox token), with the recommendation first, and set `decisions=D-…` on every gated ticket so the answer's triage finds them.

**Why:** the CEO chose to authorise workers over doing lab steps by hand (A-0025), and repeated "no change" notes hide a structural blocker. Keep vendor sign-ups (ADMP trial, A-0024) and Entra (deferred, A-0026) out of the offer: those are legal or deferred, not access.

**How to apply:** first check that the runbook and decisions-log have no earlier offer of the same access (grep for it). Scope it as narrowly as the platform allows (a pool or resource group), and make it revocable with one command. If the answer is a, follow [[ceo-action-handover]]: ticket a one-command bootstrap before filing the action.
