---
title: "ADR-0016: Entra read scopes are two root kinds, `entra_tenant` and `administrative_unit`, rendered as per-term SQL over `directory_objects` and `links`"
date: 2026-11-15
updated: 2026-11-15
status: ratified
ratified_on: 2026-11-15
ratified_by: factory-director
decision: D-0037
reviews: security-architect and ad-expert, 2026-11-15, changes folded in (provider predicate, dedicated freshness columns, NULL-negation rule, hidden membership)
owner: heramb
author: solution-architect
kind: technical
ticket: T-1131
amends: 0011-universal-search-over-inventory-pg-trgm-one-scope-renderer.md (rule 9, consequences); modules/reports.md §4.2, §4.3, §4.6
fitness: RP6 (extended), SE3 (extended), RP12 (new) — none in CI yet, so not `accepted`
---

# ADR-0016: Entra read scopes are two root kinds, `entra_tenant` and `administrative_unit`, rendered as per-term SQL over `directory_objects` and `links`

**Status:** ratified 2026-11-15 (notice D-0037) after security-architect and ad-expert review. `accepted` when RP6, SE3 and RP12 (below) run
green in `make ci`.
**Kind:** technical. **Ticket:** T-1131 (E-002, parity ADM-003). **Unblocks:** E2.6 FB-4, E2.7a FR-38, E2.7 FR-30/32/33.

## Context

ADR-0011 rule 9 and reports §4.3 say the 2a read-scope kinds are `naming_context`, `ou_subtree` and
`ou_one_level`, all AD-only. Entra rows in `directory_objects` (migration 0033) have `nc_guid` NULL,
`ancestry = '{}'`, `parent_guid` NULL and `ancestry_complete = false` (e2-7a FR-36). So `scope(a)` of §4.3
is `FALSE` for every Entra row, because it requires `a.complete`: they are indexed and unreachable in search and in
every report, **even for an account whose assignment root is `entra_tenant`**. rbac already stores the
kinds (DM-35: `entra_tenant`, `administrative_unit`, `group_members`; migration 0018) and per-target
`Authorize` already treats a tenant root as the connection (rbac.md "Root kinds"); `ReadScopes.For`
records `scope_kind_unsupported:entra_tenant` and drops the grant. The gap is only the read side.

Facts this decision rests on:

- An Entra connection's objects are all rows with `connection_id = <that connection>`. The connection **is**
  the tenant (DM-10: one Entra tenant per Entra connection, e2-7 FR-01).
- An administrative unit's members are **direct only**: AU membership is not transitive, and a group in an
  AU does not put its members in the AU ([administrative units](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units); DM-35.I2).
- `links` (migration 0012) stores DM-17 edges `(tenant, connection, source_guid, link_attr, target_guid, state)`
  with `link_attr IN ('member','primary_group')` and the index `links_by_target (tenant, connection, link_attr, target_guid) WHERE state='active'`.
  DM-17 says Entra `members` of an AU are stored as links. They are not yet synced.
- Read does not narrow on Tier-0 (DM-35.I5) and `Via` (`include_correlated`) grants contribute nothing to reads (rbac.md).

## Decision

### 1. Two root kinds, both at once; `group_members` is not part of this decision

1. **`entra_tenant`**: `root_guid` = the connection ID (schema check, migration 0018). Admits every
   `directory_objects` row of that connection (row `state` is the dataset's concern, as for AD). This is the whole-tenant read.
2. **`administrative_unit`**: `root_guid` = the AU's object ID. Admits the AU's **direct** members: the targets
   of an active `au_member` link whose source is the AU. It does not admit the AU object itself (it is a container
   whose members are the scope, as `ou_one_level` does not admit its root), and never a member of a nested
   group.
3. **`group_members` stays unsupported** (`scope_kind_unsupported:group_members`, fail closed). Entra groups
   have no closure (reports.md §3.3 `group_members`) and an AD one needs the closure join; that is its own
   design. Ticket T-2176. Specs that cite T-1131 for `group_members` (e2-6 FB-4, e2-7a §6) are
   re-pointed to that ticket.
4. **Why both:** `entra_tenant` alone gives the platform administrator and tenant-wide technician their
   reach; AUs are how Entra customers delegate (ADM-131, ADM-003) and rbac already stores them. Shipping
   only the tenant would make a scoped Entra delegate see nothing, which is the failure this ticket exists to fix.
   Cost of the second kind is one `EXISTS` term and one link attr.

### 2. The type: two new `TermKind`s

`TermEntraTenant` and `TermAdminUnit`, appended to `authz.TermKind` (zero stays unknown; values never
renumbered, because `Fingerprint` canonical form sorts by kind). `ScopeTerm{Kind, Connection, Root}` is unchanged:
`TermEntraTenant` carries `Root == Connection`. The evaluators are registered by `modules/delegation`
through `Registrar.ScopeEvaluator` like the AD ones (one per kind; Boot still fails on a duplicate).
`ReadScopes.For` rules are unchanged: same-connection, same-root, kind name equals root kind, a kind with
no evaluator is dropped. An `administrative_unit` root with a zero GUID is `scope_term_invalid`; an `entra_tenant`
root whose GUID differs from its connection is `scope_term_invalid`. Both new kinds are include **and**
exclude capable (DM-35.I3: exclusion beats inclusion); an AU exclude inside an `entra_tenant` grant is the
main use.

### 3. SQL: completeness moves from the row into the AD terms

The §4.3 guard `a.complete AND (...)` assumes every row has a parent chain. Entra rows have none and
`ancestry_complete` is false for them forever, so the row-level guard must go; but it must not
disappear for AD rows. Decision: the guard becomes part of each **AD term**, as a `CASE` so that an incomplete
row is *unknown*, which `inc` turns into false and `exc` into excluded (the existing fail-closed rules):

```
scope(a)   = COALESCE( ( G(a) ) [AND ( K(a) )] , false )                 -- no row-level a.complete

term(a, NamingContext{c, r}) = ( a.connection = $c AND CASE WHEN a.complete THEN a.nc = $r END )
term(a, Subtree{c, r})       = ( a.connection = $c AND CASE WHEN a.complete THEN ( a.object = $r OR a.ancestry @> ARRAY[$r]::uuid[] ) END )
term(a, OneLevel{c, r})      = ( a.connection = $c AND CASE WHEN a.complete THEN a.parent = $r END )
term(a, EntraTenant{c, c})   = ( a.connection = $c AND a.provider = 'entra' )
term(a, AdminUnit{c, r})     = ( a.connection = $c AND EXISTS (
                                   SELECT 1 FROM links l
                                    WHERE l.tenant_id = a.tenant AND l.connection_id = $c
                                      AND l.link_attr = 'au_member' AND l.state = 'active'
                                      AND l.source_guid = $r AND l.target_guid = a.object
                                      AND EXISTS ( SELECT 1 FROM directory_objects au
                                                    WHERE au.tenant_id = a.tenant AND au.connection_id = $c
                                                      AND au.object_guid = $r AND au.state = 'active' ) ) )
```

- **Provider is checked in SQL, not only in Go (security review B1).** `directory_objects` gains no new data:
  the anchor column `a.provider` is `(SELECT kind FROM connections …)` denormalised by the ticket C migration as a
  NOT NULL `provider text CHECK (provider IN ('ad','entra'))` set by the writer from the connection and immutable
  (trigger). Entra terms require `'entra'`; AD terms add `AND a.provider = 'ad'`. A term bound to the wrong
  connection kind returns no rows even if `ReadScopes.For` is wrong. RP6/RP12 test an Entra term bound to an AD connection.
- **A connection is one provider.** AD terms bind an AD connection and Entra terms an Entra connection
  (checked by `ReadScopes.For` from the connection kind, the same `ObjectConnections` port the token layer
  uses), so an AD row never meets an Entra term and an Entra row never meets an AD term. An AD row with
  `complete = false` is still out of scope in every grant: its AD terms are NULL (include false, exclude true), and
  no Entra term shares its connection. So **no AD row becomes visible, and none becomes hidden-then-visible, by this change.**
- The anchor gains the `tenant` column (`a.tenant`), pre-quoted at registration with the others; the row's
  tenant is RLS-fixed anyway, and the explicit key lets the `links_by_target`-led index be used.
- **A deleted or missing AU grants nothing** (DM-35.I1): the inner `EXISTS` on the AU row with
  `state = 'active'`. An AU that is deleted, restored from deleted items, or not yet synced renders
  `FALSE`, never the tenant. Restoration is not silent: `entry_state` already holds a restored root inactive.
- `a.object` is the object ID of the Entra row; the AU's own row is not admitted by its own term (rule 1.2).
- **Excludes.** Entra rows are never `NULL`-guarded away: `exc` is `COALESCE(term, true)`, and the AU term
  is NULL-free, so an Entra exclude excludes exactly its members. An AU the sync has not yet read renders
  the exclude **false** for its (unknown) members, which would widen. So an **exclude** AU term is rendered
  with a freshness guard: `excTerm(a, AdminUnit{c,r}) = ( a.connection = $c AND ( NOT EXISTS (SELECT 1 FROM directory_objects au WHERE … au.object_guid = $r AND au.state = 'active' AND au.attributes->>'members_synced' = 'true') OR <the include term above> ) )`,
  so it is `TRUE` (excluded) for every row of the connection when the AU's `au_member`
  links are not known complete or are older than the bound (`au.attributes->>'members_synced'` absent, set by the sync only after a full
  member read, cleared on a partial read). An include with an incomplete member list under-admits, which is
  safe. This is the Entra counterpart of §4.5 `ancestry_complete`; the sync ticket (D) owns the flag.
- **Budgets and shape.** The 512-term cap, the narrowing renderer (`term` is shared, so a narrowing can
  name an AU or the tenant), `ErrScopeTooLarge` and the bound parameters are unchanged. All GUIDs are bound `uuid`.
  No new string-built SQL: the `links` literals `'au_member'` and `'active'` are constants in the renderer,
  and the term's table names are pre-quoted at registration (RP1, `sqlconst`).
- **Search** consumes the same `scopeSQL` (ADR-0011 rule 11), so Entra rows become findable with no change to
  the statement, the ceiling rules (M4) or the cost model: `hits` joins `directory_objects` and applies `scope`.
  The AU `EXISTS` runs after the tenant-led key lookups on at most 3(W+1) rows, so rule 16's tenant-independence of
  blocks read is unaffected (SE5 is re-run with an AU scope in the extended SE3 world).

- **Freshness state (security review B2).** `au.attributes->>'members_synced'` is replaced by dedicated
  columns on `directory_objects` (ticket D migration): `au_members_synced boolean NOT NULL DEFAULT false` and
  `au_members_synced_at timestamptz`; Graph payloads can never write them. The exclude renders TRUE unless
  `au_members_synced AND au_members_synced_at > now() - $max_age` (bound parameter; default 2 × the sync interval
  `[PROPOSED]`). A trigger clears `au_members_synced` in the same transaction as any `au_member` link write, and the sync sets it only after a
  full member read. Hidden-membership AUs (list needs `Member.Read.Hidden`, [list members](https://learn.microsoft.com/en-us/graph/api/administrativeunit-list-members?view=graph-rest-1.0))
  and any read that returned id-only stubs or a partial page never set it. A fail-closed exclude must surface in the connection's health and in
  `scope_applied` reasons (`scope_au_exclude_stale`), so it does not look like an outage.
- **No NULL is ever negated (security review B3).** `NOT` applies only to `COALESCE(term, true)` results; the token layer and the narrowing
  use the same `inc`/`exc` wrappers. RP12 forbids an AD term under `NOT` or outside a COALESCE; RP6 adds an incomplete AD row under an exclude and under a narrowing.
- **Ids.** `directory_objects.object_guid` stores the Entra object `id` for Entra rows (not `onPremisesImmutableId` or the on-prem SID). AD and Entra
  GUIDs can in principle collide, so `connection` (and `provider`) stay on every term. One Entra connection = one tenant (an app registration authenticates against one tenant); guests carry the host tenant's id.
- **AU delete/restore.** AUs are soft-deletable ([deleted items](https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0)); a restored AU keeps its id `[UNVERIFIED]`, the root stays inactive until reactivated (DM-35.I1), and after a restore `au_members_synced` is false until a full re-read.
- **Stubs.** Graph returns members as id-only stubs when the app lacks read permission for the type; the link needs only the id, but the member's row may be absent. Sync requests user, group and device read.
- **Oracle limitation.** The oracle's `AdminUnits` and the SQL read the same `links`, so RP6 proves the renderer, not the sync; the sync is tested by ticket D against the Entra sandbox. Dataset layer must filter tombstoned Entra rows (active link to a deleted member) and keep field-level masking for role-assignable groups and privileged-role holders (E2.7a FR-38).

### 4. The oracle

`authz.Evaluator.AuthorizeRead` stays "`Authorize` minus the Tier-0 write limit, with `Via` contributing
nothing". `authz.Target` gains `AdminUnits []ObjectID`: the AUs of which the target is a *direct, active-link*
member, with the AU rows live (read from `links` and `directory_objects` back after the writer ran, as RP6
reads `ancestry` back). `Scope.covers` gains two cases:

- root `entra_tenant`: covers a target whose chain top (connection) is the root's connection, whatever its
  `Ancestors` or `Complete` (a tenant root never looked at the chain);
- root `administrative_unit`: covers a target of that connection whose `AdminUnits` contains the root.
  `Complete` is not consulted for either Entra kind; it still gates every AD kind.

Per-target `Authorize` for **writes** already uses live Graph facts (ADR-0005 rule 7 table) and is not changed;
the inventory-based `AdminUnits` is only for reads and for the oracle. Both must agree on kind semantics
(direct membership only), which RP12 checks on the Go side.

### 5. Tier-0 and restricted-management AUs

- Reads are not narrowed by Tier-0 for Entra either (DM-35.I5): an `entra_tenant` read scope reaches
  role-assignable groups and privileged-role holders, like an AD naming-context read reaches Domain Admins.
  Seeing them is the platform administrator's job; the Tier-0 write limit is untouched.
- A restricted-management AU limits *modification* by tenant-wide application permissions (DM-35.I7), not
  reads, so sync still sees their members. Restricted management blocks modification, and no read block is documented ([restricted management AUs](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management)); the live read is `[UNVERIFIED]` until ticket D tests it. If it fails the AU's flag stays unset and, per §3, an unknown AU is never widened.
- The sync's Graph permissions for AU members are the sync ticket's; they follow `graph-data-permissions-policy.md`.
- **No new privilege crosses a trust boundary:** no credential, DC code or write path is added; the new surface is a read predicate.

### 6. How RP6 and SE3 extend

- **RP6** (`Test_compiled_scope_matches_read_oracle`) adds Entra connections to its random worlds
  (rows written through the inventory writer, never inserted), AU membership edges through the links
  writer with link adds and removals, AU deletion, and AU rows with `members_synced` set and unset; scopes
  with `entra_tenant` and `administrative_unit` includes and excludes in grants and in the token layer (a token's roots stay AD subtree terms; an
  Entra token root has no evaluator and makes the layer grant nothing, as for an unresolvable root); mixed AD+Entra grants; the same oracle
  call. Mutation checks, by hand, once: dropping the AU `state='active'` guard; dropping the `members_synced`
  guard on excludes; moving the `complete` guard back to the row (Entra rows disappear, RP6 fails).
- **SE3** (the search leakage property) adds worlds in which A holds an AU scope and B holds a
  tenant scope; A's hits, counts, `more` flags and `ceiling_hit` must be equal in worlds that differ only by
  Entra objects outside A's AU. It also covers an Entra-only and an AD-only technician: each sees none of the other's rows.
- **RP12 (new, `tools/fitness/reports`, static):** the only place that names `links` or `au_member` in
  `reportsql` is the `AdminUnit` term; each Entra term is NULL-free and each AD term holds the `CASE WHEN a.complete`; no term is built with
  string formatting; `TermKind` values are append-only (golden list).

## Options considered

| Option | Why not |
| --- | --- |
| **`entra_tenant` only** | Smallest, but rbac stores AU roots (DM-35) and Entra delegation (ADM-131) is by AU. An AU-scoped technician would hold a grant that reads nothing. Rejected. |
| **AU only** | A platform administrator's tenant-wide read would need an AU of everything. Rejected. |
| **Entra rows get a synthetic `nc_guid` = connection and `ancestry_complete = true`, reusing `naming_context`** | Zero renderer change, but it overloads a kind: an Entra row is not in a naming context (DM-14), `nc_guid` NULL is invariant I9's CHECK, and a naming-context grant would then read the wrong provider. Rejected. |
| **Model the tenant as the AU's parent (`ancestry = {AU}`)** | AU membership is many-to-many and non-transitive; an ancestry array is a tree. Rejected. |
| **Per-row `provider` discriminator on the guard (`a.complete OR a.nc IS NULL`)** | A real AD row with `nc_guid` NULL and a half-built chain would be admitted. Rejected for per-term guards. |
| **Materialised `inventory_au_members` table** | Another derived table to keep in step in the writer's transaction; `links` already has the index. Revisit if RP12's plan check shows the `EXISTS` is slow at 100k AU edges. |
| **Resolve AU membership live through Graph at read** | Violates "scope is in the SQL statement" (ADR-0011 rule 10), and Graph throttles. Rejected. |

## Consequences

- Entra users and groups become findable and reportable for exactly the accounts whose assignments admit them.
  E2.6 FB-4 and E2.7a AC-43/AC-57 can proceed for the two kinds; `group_members` waits for T-2176.
- `reports.md` §4.2/§4.3/§4.6 and ADR-0011 rule 9 are amended (map update ticket, below).
- AU scopes are only as fresh as the last AU member read. An include under-admits when stale; an exclude is guarded
  by `members_synced`. The report freshness label (§6.4) names the Entra connection's sync age.
- Removing the row-level `complete` guard touches the most security-relevant line of the renderer; RP6's existing mutation
  check ("remove the guard") is re-done against the per-term form.

## Fitness function

RP6 extended, SE3 extended, RP12 new (§6). The ADR becomes `accepted` when all three run green in `make ci`.

## Follow-up tickets

Created from this ADR (ids in the ticket note). A evaluators and kinds (backend-engineer); B oracle
(`Target.AdminUnits`, `covers`) (backend-engineer); C renderer terms, `a.tenant` anchor, per-term guard, RP6 + RP12
(reporting-engineer); D AU member sync, `links` migration for `au_member` and `members_synced` (directory-engineer);
E SE3 extension (test-engineer); F map and ADR-0011/reports amendments (solution-architect); T-2176 `group_members` read root (solution-architect).
