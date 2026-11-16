---
name: erratum-guards-vs-own-examples
description: Run every example an ADR rule/erratum registers, confirms or lists through that rule's own guard or criterion before ratifying (T-0889 onprem_sid; T-1221 write-class criterion)
metadata:
  type: feedback
---

Before ratifying a fitness-rule erratum, run every term the erratum registers or allows through the erratum's own guards. Use the tool's real normaliser to do it, in a python one-liner.

**Why:** On T-0889 (2026-10-30), the ADR-0002 E-1 guard said "a term no longer than its token plus 4 chars is refused", to block `onPremises`. That same guard also refused `onprem_sid` (normalised `onpremsid`, +3), which E-1 itself registers. The build ticket's AC1 and AC2 therefore contradicted each other. The prose read fine. The arithmetic did not.

**How to apply:** For each guard, list the must-pass examples and the must-fail examples the text names. Compute both lists. If no single threshold separates them, the guard must be replaced, not tuned. Reject that as a must-fix, and send any downstream ticket carrying the guard a "wait for the rework" note.

Same check for classification criteria. On T-1221 (2026-11-01), the criterion read "config when a principal's decision sets any row". By that test, enrollment_tokens (issued_by), correlations (the reconfirm Action) and item 5's approval decisions would all be config, yet the ADR confirmed them as system. Run each confirmed table, and each numbered exception, through the criterion. When an allow-list sets `callers: []`, grep for in-package references too: a convert-row wrapper still trips the caller rule.

Round 2 (T-1221): every carve-out clause in a class test must be no wider than the list item it cites ("own credentials" vs item 1 "at first sign-in"). The test must be surface-independent, with a closed numbered list of no-Step exceptions. A qualifier such as "via the authenticated surface" lets anonymous routes escape. For a security-sensitive spec, consult security-architect in the review: the spec flow has no security stage, and that consult caught all three round-2 gaps.

Round 3 (T-1221): check the *actor word* in the definition against the surfaces the test claims. "A value a principal chooses" excluded the anonymous and CLI items, where no principal exists. Also check who may add callers to a widening allow-list row. If it is only "reviewed, not an amendment", a generic writer (any Subject) silently gains new surfaces. Make it an amendment keyed on the category.

Round 4 (T-1221, ratified): when an ADR adds a fenced source-of-truth block that a fitness check compares with a data file (`o3-widening` vs `o3-writers.json`), parse both in a python one-liner and diff them. Then grep the code for the block's callers before you ratify.

Related: [[adr-ratification-flow]], [[generator-adr-review-checks]]
