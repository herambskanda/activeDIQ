---
name: pipeline-adr-review-checks
description: Write-path/audit ADR review — token-typed write APIs create kernel import cycles; authz rules must cover every DM-35 root kind incl. Entra; CI-sourced state tables need edge cases
metadata:
  type: feedback
---

When an ADR makes a kernel type a parameter of other kernel packages' write APIs (a Step token, a Tx),
draw the import DAG yourself. Type-owner → user and user → type-owner is a Go cycle that the ADR text hides.

**Why:** T-0047 (ADR-0005, 2026-10-02) had a strong draft with both consults applied. Even so, operation
imported authz/audit, while rules 1 and 10 made authz/audit/personal import operation (their Actions(), and
config writes that take a Step). store also ran the chain statements on audit-owned tables. On top of that,
rule 7's live re-check covered only AD ancestry, while D-0001 puts Entra in v1. Rejected round 1.

**How to apply:**
- For each new type in a signature: which package declares it, and which packages must import it? Does any of
  them sit upstream of the declarer? Demand a placement subsection that names the leaf packages.
- "X runs inside store's transaction" on another owner's tables: ask for a hook plus the ownership row.
- For every authorisation re-check, walk all DM-35 root kinds (OU, group_members, entra_tenant,
  administrative_unit, include_correlated across two connections), not just "ancestry".
- For a CI-compared transitions block, test the edges: all-skipped plan, a verify_failed step under undo,
  re-plan changing a hash that approvals bind to (DC pin), bootstrap windows such as the 30-day sock-puppet rule.

Related: [[generator-adr-review-checks]], [[adr-review-allowlist-and-ownership]], [[domain-model-review-checks]]
