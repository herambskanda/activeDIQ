---
title: "platform/rbac: RBAC persistence and the operation Authorizer"
date: 2026-10-26
updated: 2026-10-27
status: draft
owner: backend-engineer
ticket: T-0367
---

# platform/rbac (DM-34, DM-35, DM-36; threat model §7.7)

Code: `internal/platform/rbac/`, `internal/modules/delegation/`; migrations `0018_authz_rbac.sql`, `0035_authz_subjects.sql`.

- **Tables** (tenant, RLS): `authz_roles`, `authz_role_permissions`, `authz_assignments`,
  `authz_assignment_roots`. Subjects are an account, a directory group
  (connection + objectGUID) or an automation policy (opaque ID owned by lifecycle); `subject_kind` + a shape
  check in migration 0035. A token is never a subject: it narrows its owner (DM-32).
- **`Authorizer`** implements `operation.Authorizer` over `authz.Evaluator`. It loads the requester's
  current assignments (own short read, so it works inside the runner's tenant transaction), builds an
  `authz.Target` from the live `authority.Facts` (target, parent chain, connection as chain top) and
  lets the evaluator decide. The requester must be a human; the chain may carry at most one `APIToken` and
  one `Automation` hop (anything else is denied).
- **Tier-0 scope (T-0173):** a target of class `tier0_scope` (GUID = connection ID) is covered only by
  a `tier0_scope` root for that connection. OU, naming-context and connection-wide roots never cover it;
  a `tier0_scope` root covers nothing else; the Tier-0 scope permission is refused on any other class.
- **Catalog:** `BuiltInRoles()` (tier 0/1/2). No Tier-2 role holds a Tier-0 scope permission: checked in
  `ValidateRoles`, and by a trigger in the schema.
- **Tenant owner (T-0436, DM-30.I4, DM-36.I4, ADM-126):** `BuiltInRoles()` seeds `tenant-owner` (tier 1, no
  permissions yet). Migration `0034_authz_tenant_owner.sql` makes it read-only, reserves the name, and refuses
  any owner assignment with `valid_until` or a future `valid_from` (trigger, AD403; so time alone cannot
  remove an owner). `OwnerAssignments` (`Grant`, `Revoke`) is the one writer: personal, unscoped grants;
  `Revoke` calls `Owners.TenantOwners` first (the per-tenant advisory xact lock) and refuses removing the
  last *active* owner (`ErrLastOwner`, a committed `rbac.owner.revoke_refused` denied event). Activity of an
  account comes through the `ActiveAccounts` port (authn's to implement). Audit: `rbac.owner.granted|revoked|revoke_refused`
  in the same tx.
- **Facts:** `directory/client.ConnectorFacts` is the `operation.LiveFacts` reader over a `Reads` port
  (the connector's Read). It answers a `tier0_scope` or store target without a read (Exists, not Tier-0),
  walks the parent chain for a directory target, and fails closed with `ErrNoReads` until the Tier-0 verdict
  source lands (T-0433): the gRPC adapter and its `client.TunnelSource` (connection → active component
  binding → fleet-hub tunnel, tenant-checked) are wired in `compose/server`.
- **Wired in** `compose/server`: `rbacAuthorizer(db)`, `directoryFacts(reads)`.

## Subjects, tokens and store targets (T-0367)

- **Group subjects (DM-36.I2):** `authz.Membership` (port, `authz/membership.go`) resolves an account's groups,
  returning only eligible ones (security groups, no weak DACL, active links); `WithMembership` enables it.
  Group assignments merge with direct ones in `Authorizer.effective`. An incomplete or failing resolution
  drops the group grants (incomplete) or fails the decision (error): never a guess. A derived membership
  carries `Via` and is gated by the hybrid rules like any correlation-derived grant.
- **Control-plane authority is personal (DM-36.I4):** tenant-owner and `authz.NeverCrosses` permissions are
  stripped from group and automation assignments at read, refused by `Grants`, and refused by the trigger
  `authz_control_plane_guard` (0035). A Go test keeps the trigger prefixes equal to `NeverCrosses`.
- **Tokens (DM-32):** `WithTokens(TokenSource)` supplies the constraint (permission subset, scope, expiry);
  effective authority is the owner's ∩ the token's. No `TokenSource` → a token in the chain is denied.
  **Automation (DM-60.I2):** a chain with an automation hop must also pass the policy's own assignments.
- **Store targets:** a target of an explicit store class (`role`, `assignment`, `settings`; empty connection) is
  a row in activeDIQ's own store. A directory class with no connection, or a store class with one, is denied
  `target_not_a_guid` (never read as a store row, which would skip the Tier-0 and ancestry facts). It is covered only by
  a `tenant` root of the same tenant (`root_kind='tenant'`, id = tenant id, no excludes). Directory and
  Tier-0 roots never cover it, and a `tenant` root never covers a directory object.
- **Tenant-owner** holds every permission over its scope (`authz.Role.has`, DM-34.I1).
- **`Grants`** (`grants.go`) writes `CreateRole`, `SetRolePermissions`, `Grant`, `Revoke` inside the runner's
  transaction. No-escalation (DM-36.I1) is `holdsOver`: the grantor's live effective assignments, resolved
  per scope root, must hold every privilege over the whole scope (a personal tenant-owner is exempt).
  Correlation-derived grants never count. **Serialisation:** `SetRolePermissions` locks the role row
  `FOR UPDATE` and `Grant` `FOR SHARE` before reading permissions and holders, so an edit and a grant by one
  actor cannot combine into an escalation under READ COMMITTED. **Revoke and narrowing are tier-checked:**
  `Revoke` needs the actor to hold the assignment's privileges over its roots, and `SetRolePermissions`
  needs the held privileges for added *and* removed permissions per holder (a personal tenant-owner is
  exempt), so a lower tier cannot end or strip Tier-0 access. The trigger skips non-active rows, so a group
  assignment whose role became control-plane stays revocable (DM-36.I4 remediation). Built-in roles are read-only; tenant-owner is granted only by
  `OwnerAssignments`. Migration 0035 grants `DELETE` on `authz_role_permissions` (removal only narrows).
- **`modules/delegation`** contributes four Actions (store targets, class `role`/`assignment`, step-up,
  audited with a before/after diff): `delegation.role.create`, `.role.update`, `.assignment.grant`,
  `.assignment.revoke`. Their permissions are control-plane. A nil `platform.Deps.Access` makes every
  Plan/Apply refuse.

- **Group-membership guard (TM-D18, `groupguard.go`):** `GroupMembershipPermissions` (add member, nest group,
  set primary group) must be declared by any Action that widens a group's reach, with the Target set to the
  group whose reach grows. `WithGroupGuard(GroupReach)` answers the role-granting groups reached (itself and
  transitively); the actor must hold every pending/active privilege of each over its scope. Unwired,
  incomplete or unresolvable answers are denied (fail closed).

**Not yet wired** (tickets filed): an `authz.Membership` implementation over inventory; the DM-32 token store
(`TokenSource`); compose passing `Deps.Access` / `WithMembership` / `WithTokens` and registering module
Actions with the runner; a `GroupReach` implementation and the group-member Actions that declare `GroupMembershipPermissions`; `control_plane` catalogue flags for the new permissions.
