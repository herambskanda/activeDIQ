---
name: review-check-ceo-answers-vs-draft-time
description: When reviewing an ADR/spec, check whether CEO decisions were answered while it was being drafted — drafts often miss them and treat settled forks as open
metadata:
  type: feedback
---

When reviewing an ADR or spec, compare the claim/draft time on the ticket with `decision list --json` answer timestamps. A draft started before a CEO answer landed will cite the fork as "open" and miss the strongest constraint.

**Why:** On T-0002 (ADR-0001, 2026-10-02), the architect claimed at 02:18 UTC, but D-0002 (deployment) was answered at 02:23. The ADR called "Windows-only vs cross-platform" an open CEO fork and used it to argue against .NET, and the draft CEO notice repeated the stale framing. It took a reject round-trip to fix.

**How to apply:**
- On every ADR/spec review, grep the draft for "CEO fork", "ADR-0002" and "pre-empt", and check each against answered D-ids.
- Also check the fitness-function wording against the testing-playbook conventions; `//go:build` tags collided.
- Rewrite the ratification notice yourself; don't trust the author's draft notice framing.

Related: [[adr-ratification-flow]]
