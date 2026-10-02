---
name: adr-review-allowlist-and-ownership
description: Module/import ADR review — allowlist matrices must cover every existing and required package; table-ownership rules must be run against every domain-model DM owner line
metadata:
  type: feedback
---

When an ADR makes an import matrix an **allowlist** ("anything not allowed fails", "changing it needs a superseding ADR"), check that it covers every package that exists or is required. A missing row is a must-fix, not a nit. When it sets ownership rules, run every DM-* owner line in the domain model through them.

**Why:** On T-0045 (ADR-0003, 2026-10-02), the draft mapped every blueprint §2 bypass to a check and looked ratifiable. But it had no matrix row for `compose/config`, which already existed in the tree, and no column for `webui`, which compose/server must import. Its owner-key roots also excluded `internal/connector`, while DM-11 is owned by `connector/credential` and split across two owners. And finding F1 deferred to a ticket that was already done and contradicted DM-10/13/21. Rejected once, with all the nits bundled.

**How to apply:**
- `ls internal/*/` and check the root packages (aggregators such as Deps/Services) against the matrix rows and columns.
- Grep `^### DM-` in domain-model.md. Check that each owner resolves under the rule, that no lower layer reads a table a module owns, and that no entity has split owners.
- Check the status of every ticket that "decides later". A done ticket can't hold an open decision.
- Bundle the nits into the same reject, so the next pass can ratify.

Related: [[blueprint-review-link-graph]], [[adr-ratification-flow]], [[domain-model-review-checks]]
