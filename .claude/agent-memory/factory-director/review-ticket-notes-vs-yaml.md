---
name: review-ticket-notes-vs-yaml
description: On contract/spec reviews, check each security note on the ticket against the YAML text itself, not the worker's commit message or advance note
metadata:
  type: feedback
---

When a ticket carries a security-architect note (e.g. "needs a documented held-for-approval answer"), grep the
deliverable for it directly. T-0892 (2026-10-31): the commit message said "202 when held for step-up per SX-4",
but the YAML said only "the gate held", OperationRef had no hold reason, and the new undo route lacked
401 StepUpRequired. The sibling fix ticket (T-0979) covered only the pre-existing routes.

**Why:** worker summaries describe intent; the reviewer must verify the artefact. New routes a ticket adds fall
between the cracks of fix tickets that were scoped against the old file.

**How to apply:** for each note on the ticket, find the exact YAML lines that answer it. For each new route, ask
whether any existing security finding (R-n) applies to it too, and who owns that. Mirror kernel enums
(e.g. operation/holds.go) as open response enums. Related: [[review-check-ceo-answers-vs-draft-time]]
