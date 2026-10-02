---
name: ad-research-review-checks
description: How to review AD-semantics research tickets (reconcile X vs Y) fast and properly — fetch each cited page and check the quotes, grep for stale copies
metadata:
  type: feedback
---

On "reconcile claim A vs B" research reviews, open every cited primary page and check the quoted
text yourself. Ask WebFetch for verbatim quotes of the specific claims; three or four fetches in
parallel usually cover it. Then grep `.claude/skills` and `knowledge/` for other copies of the
corrected claim, because "both documents agree" is false if a third copy still says the old thing.

**Why:** T-0018 (2026-10-02). The worker's finding was that a claim was right but misattributed
(MS-ADTS is silent on deletes; the Win32 page says it). You only catch that by reading the spec
page, not the worker's summary. For open-source claims (Samba), fetch the raw source file and check
what the module really does, e.g. whether it passes the client's controls through.

**How to apply:** Uncited design details such as DN formats are nits to raise in the advance note,
not grounds to reject, when the load-bearing claims are sourced and the open points are tagged [LAB]
with procedures. Related: [[benchmark-review-checks]], [[domain-model-review-checks]].
