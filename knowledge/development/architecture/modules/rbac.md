---
title: "platform/rbac: RBAC persistence and the operation Authorizer"
date: 2026-10-26
updated: 2026-10-30
status: draft
owner: backend-engineer
ticket: T-0367
---

# platform/rbac (DM-34, DM-35, DM-36; threat model §7.7)

Code: `internal/platform/rbac/`, `internal/modules/delegation/`; migrations `0018_authz_rbac.sql`, `0037_authz_subjects.sql`, `0058_authz_ou_one_level_root.sql`.

- **Tables** (tenant, RLS): `authz_roles`, `authz_role_permissions`, `authz_assignments`,
  `authz_assignment_roots`. Subjects are an account, a directory group
  (connection + objectGUID) or an automation policy (opaque ID owned by lifecycle); `subject_kind` + a shape
  check in migration 0037. A token is never a subject: it narrows its owner (DM-32).
- **`Authorizer`** implements `operation.Authorizer` over `authz.Evaluator`. It loads the requester's
  current assignments (own short read, so it works inside the runner's tenant transaction), builds an
  `authz.Target` from the live `authority.Facts` (target, parent chain, connection as chain top) and
  lets the evaluator decide. The requester must be a human; the chain may carry at most one `APIToken` and
  one `Automation` hop (anything else is denied).
- **Tier-0 scope (T-0173):** a target of class `tier0_scope` (GUID = connection ID) is covered only by
  a `tier0_scope` root for that connection. OU, naming-context and connection-wide roots never cover it;
  a `tier0_scope` root covers nothing else; the Tier-0 scope permission is refused on any other class.
- **Root kinds (DM-35):** `naming_context`, `ou_subtree`, `ou_one_level`, `entra_tenant`, `tier0_scope`, `tenant`.
  `ou_one_level` (T-0881, migration 0058) reaches the **direct children of an OU only**: a target is covered
  when its nearest parent (`Target.Ancestors[0]`) is the root; the OU itself and anything deeper are not.
  It is an include root only (the schema and `validRoots` refuse it as an exclude) and its GUID is an OU's,
  never the connection's (the target chain ends in the connection). `authz.ScopeRoot.OneLevel` carries the
  narrowing: `Scope.covers` honours it, and `CheckGrant` containment lets a one-level grantor root contain only
  the identical one-level root (never a subtree below it), while a subtree grantor root contains a one-level
  root beneath it. `Authorizer.resolve` sets `OneLevel` from the kind whatever a `RootResolver` returns. Excludes
  of such an assignment are ordinary subtree excludes and beat the include. The object view fails closed on a
  root kind it does not know (a zero root: the scope covers nothing), so a new kind is never read as a subtree.
  The OpenAPI `AssignmentRootKind` enum does not list `ou_one_level` yet (the API follows the store).
- **Read scopes (T-0882):** `ReadScopes.For(ctx, tx, tenant, chain, perm)` is the one producer of directory
  read-scope predicates (`authz.ReadScope`); reports and search consume it and nothing else renders scope
  (modules/reports.md §4). `NewReadScopes(authorizer, evaluators, owner, conns)` reuses the Authorizer's
  assignment source, group membership, token source and clock, so the read scope and per-target `Authorize`
  read the same facts. One grant per account or group assignment that holds `perm`: its include terms minus its
  exclude terms, each term from the EP-6 `ScopeEvaluator` of the root's kind (`authz.ScopeEvaluator`; rbac
  reaches it through the `ScopeEvaluators` port, which `module.Contributions` satisfies).
  - A root kind with no evaluator (`entra_tenant`, `tier0_scope`, ...) contributes nothing and records
    `scope_kind_unsupported:<kind>`; one such **exclude**, or any root that does not become a valid term, drops
    the whole assignment (`scope_term_invalid`). The tenant root contributes nothing to directory datasets.
  - An evaluator is module code, so every term is checked: same connection, same root, and a kind whose name is
    the root kind (a broader kind than the root's, or an unknown one, is refused).
  - Correlation-derived (`Via`) assignments contribute nothing (`scope_correlated_grant_not_applied`); Tier-0
    does not narrow reads (DM-35.I5), so the producer does not look at it.
  - A token in the chain is a separate layer, AND-ed with the grants: its `Scope` roots become subtree (or, for
    a one-level include, one-level) terms, the connection resolved through the `ObjectConnections` port over
    inventory. A zero or unresolvable root makes the layer grant nothing; an expired token or one without
    `perm` is `authz.ErrTokenRefused`. A chain with an automation hop, a second token, or a non-human
    requester is `ErrUnsupportedChain`.
  - A disabled owner (`OwnerStatus` port over the account store), or one with no assignments, is
    `authz.ErrOwnerDead`. An owner who holds assignments but none with `perm` gets an Empty scope.
  - The read oracle is `authz.Evaluator.AuthorizeRead`: `Authorize` minus the Tier-0 write limit, with `Via`
    grants contributing nothing. `Test_ReadScope_matches_read_oracle` holds the terms to it over random forests,
    tokens and `ou_one_level`.
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
  incomplete or unresolvable answers are denied (fail closed). `inventory.Reach` implements `GroupReach` over
  the DM-17 member and primary-group edges (Complete false for a non-group target, a group with no active
  inventory row — unsynced, out of scope, another tenant's GUID — or a closure beyond `MaxGroups`; `Path` is left
  empty because the source returns the closure, not the chain); compose wires it in `rbacAuthorizer`; `inventory/reach_authz_test.go` runs it with the real Authorizer over Postgres
  (inner⊂middle⊂outer). **The guard keys on the permission:** an Action that changes group membership but declares a
  different permission skips it, so every group-member Action ticket must declare one of
  `GroupMembershipPermissions`. The Target rule is enforced twice:
  `Descriptor.TargetClass` ("group") is checked on every planned step by the runner, and
  `Test_group_membership_actions_target_the_group` (compose/server) fails when a registered Action with a
  `GroupMembershipPermissions` permission does not declare it.

**Not yet wired** (tickets filed): an `authz.Membership` implementation over inventory; the DM-32 token store
(`TokenSource`); compose passing `Deps.Access` / `WithMembership` / `WithTokens` and registering module
Actions with the runner; the group-member Actions that declare `GroupMembershipPermissions`; `control_plane` catalogue flags for the connections.* and inventory.tier0_* Actions (T-0616).

**Control-plane flag (T-0472):** `operation.Descriptor.ControlPlane` marks an Action whose permission is in an `authz.NeverCrosses` family. The four `delegation.*` Actions carry it; `Test_control_plane_flag_catalogue_matches_never_crosses` (compose/server) holds the flag to the rule. Their input schemas (`RoleCreate`, `RoleUpdate`, `AssignmentGrant`, `AssignmentRevoke`) are in `api/openapi/modules/delegation.yaml`; the wire members are camelCase and `delegation/contract_test.go` keeps the Action input types and the generated contract types in step.
