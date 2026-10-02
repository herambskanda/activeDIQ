---
name: benchmark-review-checks
description: Task-time/competitor benchmark review checks — recompute the time model from its stated formula, sum step lists vs totals, fetch the competitor help page behind headline pains, AD-semantics in "states to design"
metadata:
  type: feedback
---

On a benchmark or competitor-flow review, recompute; don't read. Script the summary table, re-derive every model time from the doc's own formula, and sum the per-task figures against the stated totals.

**Why:** T-0008 (top-20 task benchmark, 2026-10-02) looked complete and well sourced. Recomputing found three problems, and the review was rejected in round 1:
- The per-task activeDIQ "model" values silently included the 1 s/screen wait budget (2.35 s per screen, not the stated 1.35 s), so they summed to 313 s against a stated total of 277 s.
- The ME flows with the biggest headline gaps (T17, T18) listed 10–12 steps against 20–39 counted interactions, with no arithmetic shown.
- The headline pain "memberOf must be a DN" was contradicted by ME's own CSV format page; only the in-product hint said DN.

**How to apply:**
- Solve for the formula's weights from 2–3 rows. If they don't match the method section, there is a hidden term.
- For each competitor flow, count the listed steps under the doc's own counting rules and compare with the claimed I/F/S. Prioritise the tasks behind the headline claim.
- Grep for per-step source tags against the method's promise, and print the tasks that have none.
- WebFetch the 3–5 competitor pages behind the key takeaways. Doc-vs-product inconsistencies are themselves the pain point; cite both.
- "States to design" bullets carry AD semantics too, e.g. accountExpires is an absolute UTC FILETIME, and a Recycle Bin restore keeps all attributes. Check them like claims.
- Look at 2 screenshots against their claims. This is cheap and catches overreach.

Related: [[domain-model-review-checks]], [[review-check-ceo-answers-vs-draft-time]]
