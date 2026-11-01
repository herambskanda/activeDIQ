---
name: erratum-guards-vs-own-examples
description: When an ADR erratum adds a validation guard (length, prefix, regex) to a fitness rule, run every example the erratum itself registers or allows through that guard before ratifying
metadata:
  type: feedback
---

Before ratifying a fitness-rule erratum, run every term the erratum registers or allows through the erratum's own guards. Use the tool's real normaliser to do it, in a python one-liner.

**Why:** On T-0889 (2026-10-30), the ADR-0002 E-1 guard said "a term no longer than its token plus 4 chars is refused", to block `onPremises`. That same guard also refused `onprem_sid` (normalised `onpremsid`, +3), which E-1 itself registers. The build ticket's AC1 and AC2 therefore contradicted each other. The prose read fine. The arithmetic did not.

**How to apply:** For each guard, list the must-pass examples and the must-fail examples the text names. Compute both lists. If no single threshold separates them, the guard must be replaced, not tuned. Reject that as a must-fix, and send any downstream ticket carrying the guard a "wait for the rework" note.

Related: [[adr-ratification-flow]], [[generator-adr-review-checks]]
