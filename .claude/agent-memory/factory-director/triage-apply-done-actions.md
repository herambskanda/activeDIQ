---
name: triage-apply-done-actions
description: In triage, treat done CEO actions like answered decisions — sweep their done notes against blocked tickets; serialise shared-lab tickets
metadata:
  type: feedback
---

Every triage, compare `action list --json` entries done since the last full triage against the notes of
blocked tickets ("re-ready when A-… is answered"), and read each done note: it may grant a path
(A-0025 WinRM on dc1), defer the work (A-0026 Entra after M1), or close with no artefact.

**Why:** On T-0838, 10 tickets stayed blocked for 24 h after A-0025 authorised WinRM, and A-0030 re-asked the
CEO for something they had deferred. Nothing flags an answered action the way it flags an answered decision.

**How to apply:**
- Grant → unblock the tickets it gates. Check each AC really needs only what was granted (T-0635 needed dc1 only; T-0409 needs fs1, so it stays blocked).
- Deferral → move the tickets to the later milestone and withdraw any duplicate action with an explanatory done note.
- When several unblocked tickets share one mutable lab host, serialise the disruptive ones with depends_on (keep them blocked) and give the rest a flock convention until tooling exists ([[triage-blocked-on-another-ticket]]).
