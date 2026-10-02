---
name: spike-review-checks
description: How to review a spike ticket fast — verify upstream claims with gh api, check follow-up tickets' expectations, route security review to the productising ticket
metadata:
  type: feedback
---

- Check every upstream library claim (release tag contents, PR numbers and dates, commits ahead) with `gh api repos/<o>/<r>/pulls/N`
  and `compare/<tag>...<sha>`. It takes one call and caught nothing false on T-0023, but spike findings overturn ADR premises.
- When a spike disproves an ADR premise, create the amendment ticket (solution-architect, director + notice) in the review itself.
  Also look for stale licence-register rows that repeat the old premise.
- Read the follow-up gate tickets the spike created (e.g. T-0133). Check their expected evidence against the sources: T-0133 expected
  event 3039 for a CBT mismatch, but the Microsoft table says 3040.
- Integration tests must assert the rejection *reason* (error code), not just failure. The spike also needs a control run with
  enforcement relaxed, which proves the rejection comes from the feature under test.
- A spike ticket advances straight to done (no security stage). If it is tagged security-sensitive, put the security-architect review
  on the ticket that productises the code.

- Benchmark spikes: read how each latency histogram is filled (per-op vs `AddN(d, n)` event-weighted) and what batch
  size actually ran (flush timer vs cap); check the recommendation against the spike's own table (T-0026 picked the
  slower mode); grep ratified ADRs for the "discovery" (ADR-0002 already had COPY-vs-RLS); fetch the cited source behind
  the threshold (MS says 3,000/s "on average", not a ceiling).
- Round 2: when a review changes a recommendation, re-read the follow-up tickets' title and AC, not just their notes.
  A note saying "AC is stale" doesn't change the AC (T-0143 still said copy-stage). `ticket set` can't edit
  title or AC, so cancel and re-ticket (T-0146).

**Why:** T-0023 and T-0026 (2026-10-02). **How to apply:** every spike review.
