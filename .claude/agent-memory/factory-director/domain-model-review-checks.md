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
- On a rework, trace every **new authorization path** back to the attribute it joins on, and ask who can write that attribute. Round 2 of T-0006 added "grant through a matched correlation" (DM-36.I2). DM-20 matched on onPremisesImmutableId, which Entra admins can write on cloud-only users, so the path ran Entra admin → AD authority. DM-30.I5 had already refused that same attribute. The gate is a read-only property: onPremisesSyncEnabled.
- For every gate that reads a Graph or tenant setting, open that API's permission table. If it lists no application permission, or needs a Global Administrator, the app-only connector (ADR-0002 rule 7) cannot evaluate it: it must be an attested fact, not a live read. On T-0006 round 3, gate (f) read `/directory/onPremisesSynchronization`, which supports delegated access only and only for a Global Administrator. Failing closed on it would have silently killed hybrid parity.
- A gate that rests on a periodic human attestation creates an availability cliff: on expiry, every grant behind it drops at once. Route owner alerting to the plan ticket (T-0031 on T-0006 round 4), and file the customer-visible prerequisite as a notice when you advance (D-0009).
- AC2 script: parse mixed ID lists like `ADM-116…119, 121`. A naive regex reported 23 false misses.
- On an "align DM with TM" ticket, diff each "only X" sentence in the binding doc against "X or Y" in the aligned doc. On T-0061, TM rule 5 said "assigned only to the account itself", but DM-36.I2 added "or a group in its own directory".
- For every enforcement backstop (registry or flag check), run the exact permissions it exists to catch through its predicate (kind, namespace, who registers it). On T-0061, an admin-kind-only check missed the action-kind `connections.*` permissions, and kernel packages never call the Registrar.
- Put cheap fixes for sibling tickets (wrong paths, allow-lists, missing state transitions) straight into notes on those tickets, so the reject note stays about this deliverable.

Related: [[review-check-ceo-answers-vs-draft-time]], [[blueprint-review-link-graph]]
