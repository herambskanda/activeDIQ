---
name: search-meta-lessons
description: T-1097 search hit metadata - derive chips through the users report dataset, fixture traps, Entra cloud-only rule
metadata:
  type: project
---

- Derived states (locked/password/expiry) are reachable only via `report.Resolve` + `reportsql.Compile` on `usersDataset()`; `reportsql.ExecAll` (no cursor) added for bounded keyed lookups. Searcher builds its own one-dataset Registry in NewSearcher.
- Derivation fixtures need `SID` and `InputsRead(15)` plus a SetDomainPolicy with PSOsReadAt, else every policy state is unknown (eligible() uses sid).
- Search default group limit is 5: tests with >5 hits must pass Limit.
- Entra rows: state 'active' (not 'live'); cloud-only = on_prem_sync_enabled IS NOT TRUE, not cloud-managed; groups also need attributes ? 'onPremisesSyncEnabled'. Never cloud_seen_at (sticky). Entra connection create needs CredentialID.
- Scope terms are NC/subtree/one-level only, so Entra rows cannot be admitted by search yet; cloud-only is tested at SearchMetadata.
- T-1096 branch was not on main when T-1097 started: merged factory/T-1096 into the branch.
