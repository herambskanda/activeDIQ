---
name: adr-ratification-flow
description: How the director ratifies a technical ADR at spec review in one pass — what to set, what not to set yet, and where residual nits go
metadata:
  type: feedback
---

When a technical ADR passes review, ratify it in the same session. Send residual nits to the ticket that implements them, not into another reject round.

**Why:** On T-0002 (ADR-0001, 2026-10-02), the second review found all four must-fix items closed. Two small fitness-function wording gaps were left: `unix`/`race` tags and a Rust PAM crate passing F1. Rejecting again for those would have stalled every downstream ticket. A note on T-0022 (the fitness-stack chore) carried them instead.

**How to apply:**
- Re-review: run `git show <rework commit>` and tick each numbered must-fix item against the diff. Don't re-read the whole ADR cold unless the diff touched its Decision.
- Order: file the notice first (`decision new --kind notice`, ≤150 words, plain language, framed by the CEO's own D-ids), then set frontmatter `status: ratified`, `decision: D-…`, `ratified_on`, `ratified_by`, and the Status line.
- Do **not** set `fitness` or `accepted_on` at this point. Those belong to the `accepted` rung.
- Log the ratification in `decisions-log.md` and `state-of-the-product.md`, commit by explicit path, then advance.

Related: [[review-check-ceo-answers-vs-draft-time]]
