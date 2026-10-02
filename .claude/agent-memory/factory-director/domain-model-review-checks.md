---
name: domain-model-review-checks
description: Domain-model/spec review checks — script the ME-concept map against scope lock §3.3, append-only vs persisted lifecycle states, non-linked AD reference attributes, Entra scope expressibility
metadata:
  type: feedback
---

On a domain-model or concept-map review, script the AC2-style mapping check. Don't trust the author's "every concept is mapped" claim.

**Why:** On T-0006 (domain model v0, 2026-10-02), the draft was strong: 54 entities, 13 ad-expert fixes, the author's own script for AC1. Diffing the scope lock §3.3 ADM IDs against the §9 IDs still found real unmapped concepts. GPO links (ADM-073/077/148) were missing. Entra delegation (ADM-131) could not be expressed by the scope root kinds. Privacy erasure (ADM-207) collided with the append-only hash chain. Rejected round 1.

**How to apply:**
- Regex the v1 ADM IDs out of `v1-scope-options.md` §3.3. Expand ranges (`…`, comma lists) in the doc's map section and print the leftovers with their CSV description. Then judge each: concept vs. pure UI feature.
- Grep for append-only entities that have multi-state lifecycles. If the notation says "a state is persisted", that is an UPDATE the X5 fitness check forbids. Require derived states.
- For every AD reference that is not a linked attribute (gPLink, and anything else a DN string carries), ask how it becomes a GUID edge. X3 forbids DN joins. Check the schema page for "Link-Id: -".
- For every scope or evaluation rule built on AD ancestry, ask how it evaluates for Entra, which has no NCs and no ancestry.
- Pairs of must rows can break each other: SSO accounts (ADM-143) + group delegation (ADM-128) needed a directory binding on Account.
- Put cheap fixes for sibling tickets (wrong paths, allow-lists, missing state transitions) straight into notes on those tickets, so the reject note stays about this deliverable.

Related: [[review-check-ceo-answers-vs-draft-time]], [[blueprint-review-link-graph]]
