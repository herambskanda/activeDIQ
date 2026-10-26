---
title: "platform/rbac: RBAC persistence and the operation Authorizer"
date: 2026-10-26
updated: 2026-10-26
status: draft
owner: backend-engineer
ticket: T-0324
---

# platform/rbac (DM-34, DM-35, DM-36; threat model §7.7)

Code: `internal/platform/rbac/`; migration `0013_authz_rbac.sql`.

- **Tables** (tenant, RLS): `authz_roles`, `authz_role_permissions`, `authz_assignments`,
  `authz_assignment_roots`. Subjects are console accounts only; group, automation and token subjects
  grant nothing until they have persistence.
- **`Authorizer`** implements `operation.Authorizer` over `authz.Evaluator`. It loads the requester's
  current assignments (own short read, so it works inside the runner's tenant transaction), builds an
  `authz.Target` from the live `authority.Facts` (target, parent chain, connection as chain top) and
  lets the evaluator decide. A chain with a token or automation in it is refused.
- **Tier-0 scope (T-0173):** a target of class `tier0_scope` (GUID = connection ID) is covered only by
  a `tier0_scope` root for that connection. OU, naming-context and connection-wide roots never cover it;
  a `tier0_scope` root covers nothing else; the Tier-0 scope permission is refused on any other class.
- **Catalog:** `BuiltInRoles()` (tier 0/1/2). No Tier-2 role holds a Tier-0 scope permission: checked in
  `ValidateRoles`, and by a trigger in the schema.
- **Facts:** `directory/client.ConnectorFacts` is the `operation.LiveFacts` reader over a `Reads` port
  (the connector's Read). It answers a `tier0_scope` or store target without a read (Exists, not Tier-0),
  walks the parent chain for a directory target, and fails closed with `ErrNoReads` until the gRPC
  adapter is wired.
- **Wired in** `compose/server`: `rbacAuthorizer(db)`, `directoryFacts(reads)`.
