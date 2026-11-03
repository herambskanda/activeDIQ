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
- A strategic-fork ADR whose CEO answers already exist (ADR-0002 implements D-0002 and D-0003) needs no new directional decision. Ratify it by applying those answers. The notice covers only the calls the factory made inside them, and `decision:` lists the answer D-ids plus the notice.

- The approving advance **is** the ratification. Set the fields and the notice before you run `ticket advance`, never "later". Missed cases (found 2026-11-01, T-1145): T-0865/ADR-0010 had neither. T-0713/ADR-0008 had a notice but no fields. Either gap blocks the `accepted` rung (T-0968).
- Never advance an ADR ticket to done with "ratify after security review". The flow does not route it back, so T-0142 (ADR-0006/0007) went review → done with no security stage. Reject it or route it to security-architect instead. When sweeping, also look for ADRs that another agent authored and solution-architect reviewed (ADR-0009). Those wait for the director.

- A notice is published copy, so rule 7 applies to it. Grep the research for every competitor or parity line before filing. On T-1314 (2026-11-02) "ME ADM-003 has no fuzzy" came from my own rejection note, not from research, so D-0024 had to be withdrawn and refiled as D-0025.

Related: [[review-check-ceo-answers-vs-draft-time]]
