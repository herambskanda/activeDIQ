// Package rbac is RBAC persistence (DM-34 Role, DM-36 RoleAssignment) and the operation.Authorizer
// built over authz.Evaluator. It loads a principal's current assignments from the tenant's tables,
// turns the live facts the runner read about the target into an authz.Target, and lets the evaluator
// decide: role ∩ scope, deny by default, Tier-0 never lifted.
//
// Scope rules (T-0173):
//   - A target of class tier0_scope (a connection's Tier-0 scope) is covered ONLY by an assignment
//     holding a tier0_scope root for that connection. An OU, naming-context or connection-wide root
//     never covers it, however broad.
//   - A tier0_scope root covers nothing else, and a Tier-0 scope permission is refused on any other
//     class of target.
//   - No built-in Tier-2 role holds a Tier-0 scope permission (Catalog, checked at build and by a
//     trigger in the schema).
//
// TM-D19 rule 5 (backing-object guard) is enabled by WithBackingGuard(Backing, RootResolver); without
// it every permission in BackingObjectPermissions is refused. The two ports are implemented here
// over narrower ports so this package never reads another module's tables:
//   - NewBacking(AccountIndex, PeerIndex): the accounts resting on the object (authn.AccountIndex:
//     directory accounts and sso accounts bound by oid or onprem_sid) plus those on every object
//     correlated to it in any DM-20 state but removed, both directions. Complete only when every
//     read succeeded. compose/server adapts authn and directory/inventory to the two indexes.
//   - NewRootResolver(FactsReader): a scope root's ancestor chain read live through the directory
//     client, unpinned (a read of a container); an unreadable or partial chain is not Complete.
//
// Only a human requester acting directly is authorised for now: group, automation and API-token
// subjects have no persistence yet, so a chain with one in it is refused (fail closed).
package rbac
