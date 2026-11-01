---
name: conflicting-ceo-holds
description: When a newer CEO hold/scope instruction contradicts an older per-ticket park, apply the newer one narrowly to goal-serving tickets and file a notice instead of a question
metadata:
  type: feedback
---

When an older CEO park note on tickets ("do NOT unblock before M1 accepted") conflicts with a newer
direction ("the factory runs M2a only"), the newer one wins. Apply it only to tickets that serve the
milestone *goal* (not just its tag), and file one `notice` listing exactly what was released,
cancelled and kept parked. Don't spend a directional decision on it.

**Why:** T-0879 (2026-10-30). Seven M2a-tagged tickets had sat parked through several triages
because nobody reconciled the two instructions. Ready was 0 while M2a needed work. Two of the seven
had already been overtaken by newer tickets.

**How to apply:** For each parked ticket, check its deps (done?), the milestone goal text and the
m2-plan scope, and look for overlap with newer tickets. A newer ticket that says "remainder of T-x"
means you can cancel T-x and move its gates over. Related: [[triage-blocked-on-another-ticket]].

**Dated holds:** a CEO hold that names a milestone target ("M2a only, target 2026-11-01") gets one
directional question on that date if the milestone is still open. Recommend the narrowest option
that keeps the CEO's priority, such as one slot for lab-bound or security work. Unanswered means
the hold stands, so file it with no default. Earlier triages copied "no change" onto 19 held tickets
for two days without asking. (T-1147, D-0016)
