---
name: stored-result-contract-review-checks
description: Module-contract review where results are stored and scope is rendered in SQL — who may read stored rows, token AND layer, stored-vs-live ancestry, fragment scoping, run state Go types
metadata:
  type: feedback
---

When a contract computes a result under one caller's scope and stores it (report runs, exports, deliveries), ask **who may read the stored result later**. Ask it separately for page, export, reuse and link reads, and again after that caller's scope shrinks.

**Why:** T-0865 (reports contract, 2026-10-30) was a strong draft: the code-state table was accurate, FR coverage was complete and the ADR was sound. It was still rejected with 9 must-fixes. It had no run-read rule, so any `reports.export` holder could export another admin's domain-wide run by ID. Its `ReadScope` (a union of grants) could not express a token's scope, which `authz.Authorize` ANDs separately at authz.go:304. And its SQL trusted stored `ancestry`, which inventory never rewrites when an OU moves, while `Authorize` refuses `!Complete`. A security-architect consult found the token and ancestry issues. I verified both in code before relying on them.

**How to apply:**
- For spec tickets tagged security-sensitive with SQL or scope rendering, run a security-architect consult in review. Give it the files, not my findings. Then check its claims against code (grep the cited lines).
- When a SQL predicate replaces a live authz check, compare its inputs with what `Authorize` reads: token scope, completeness flags, live versus synced facts.
- For a boolean formula, require explicit parentheses. Check zero roots under `NOT`, and NULLs inside `CASE` (`COALESCE(…, false)`).
- Fragments and joins: every alias over a directory table must be scoped. Counts, labels and names leak otherwise.
- The AC asks for "Go-level type names" for states, so SQL CHECK text alone fails. Also require a transitions table and an interrupted-run or retry rule.
- Masking an identity column isn't enough. Hold every *other* projected column of a masked or edge relation to a type allowlist: no text, no jsonb. The T-0865 rework fixed Rel but left MaskAnchor open. That was a nit for the B2 ticket, not a reject, because RP11 backstops it.
- Re-review: diff only the rework commit against the M-list. One pass was enough for T-0865.
- Before review, check whether the PM split any ticket the deliverable names. A cross-ticket `cancel` from a review stage was blocked by the permission classifier; notes were allowed. Leave cancels to triage.

Related: [[pipeline-adr-review-checks]], [[derived-state-retention-pins]]
