---
title: "Spec: AD Explorer (ADM-004), the OU-tree read API and screen"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: heramb
author: solution-architect
ticket: T-1838
epic: E-007
milestone: M2b
parity: [ADM-004]
scope: trimmed
---

# Spec: AD Explorer, the OU-tree read API and screen (ADM-004)

> A technician opens `/directory/explorer`, sees the OU tree they are allowed to see, starting at
> their own scope roots, clicks a container and gets its contents as a standard table. Every row
> comes from the inventory, is keyed by `objectGUID`, and is trimmed by the same renderer that trims
> search and reports. No live directory call is made.

Inputs: [IA §7.2](../design-system/information-architecture.md) (screen), DM-16 and DM-35 in the
[domain model](../../development/domain/domain-model.md), [ADR-0011](../../development/decisions/0011-universal-search-over-inventory-pg-trgm-one-scope-renderer.md)
(one producer, one renderer, scope before every limit), ADR-0003/0013 (modules register through the
registrar), ADR-0004 (OpenAPI first). Migration `0033_inventory_objects.sql` and `0059_inventory_ancestry_complete.sql`
are the tables this spec reads.

## 1. Scope (the trim)

**In v1 (M2b):** browse the tree of containers (OU, container, domain head) per AD connection;
list a container's contents (any kind) as a paged table; deep link by GUID; freshness footer;
Tier-0 flag shown on nodes; empty-OU and "mis-placed object" browsing falls out of the table
(filter by kind is client-side over the page, not a new query).

**Not in v1 (each is a later ticket, not a TODO in code):** the object tabs of ME's Explorer
(Properties, Security, Entitlements, History: they belong to the object page, ADM-005/008+);
any write or drag-and-drop move (writes are Actions, ADR-0005; no write is on this screen);
Entra objects and administrative units (no ancestry, DM-16.I9; the screen is AD-only);
browsing the Deleted Objects container (a different feature, see §6.2); counts of descendants.

## 2. Decisions

| # | Decision | Why |
| --- | --- | --- |
| X1 | **Source is the inventory only.** Table read: `directory_objects` (RLS, `tenant_id` first), nothing else. No LDAP, no connector call, no `client` import. | Same as ADR-0011 rule 1: two sources of "who is in my scope" disagree. |
| X2 | **Keys are GUIDs.** Path and body identity is `objectGuid` (uuid). The API never returns or accepts a DN, and no DN is inside a cursor. | DM-16.I1/I2. A descendant's display `dn` is not yet re-derived on a parent rename (domain model "Realised so far", T-1197); a DN-built path would be a stale parent. |
| X3 | **Trim = the one renderer.** A new exported entry `reportsql.CompileTree` beside `CompileSearch` fills its scope position with the existing `planScope`/`scopeSQL`. The producer is `rbac.ReadScopes.For(…, directory.read)`. No per-row `ReadScope.Admits`, no scope copied into a column, no second renderer. | ADR-0011 rules 10 and 11. Needs ADR-0011 amendment E3 (SE1 widened to `CompileTree`), ticket T-2086. |
| X4 | **Roots are computed, not configured.** A root is a live container row the scope admits whose parent is the NC's absence (`parent_guid IS NULL`) or a live row the scope does **not** admit. Same renderer applied to the row and to its parent in one statement. The test only decides "this admitted row is a root"; it never returns, names or logs a non-admitted parent's GUID, name or DN. | "A scoped technician's tree starts at their scope roots" without ever naming a hidden ancestor. |
| X5 | **Hidden = absent.** A GUID that does not exist, is not live, or is not admitted answers the same `404 not_found`, same body. Never 403 for an object. | No existence oracle for hidden OUs. |
| X6 | **Explorer returns `state = 'live'` rows of AD connections only** (`nc_guid IS NOT NULL`). | §6.2. |
| X7 | **Lazy and keyset-paged.** Tree nodes load one level at a time; every list is a keyset page; no OFFSET. | §4. |
| X8 | **No `dn` in any Explorer response.** Name shown = `rdn` value (or `display_name`), path = GUID chain. | X2. |
| X9 | **Module shape.** `internal/modules/explorer` (backend-engineer) registers through the registrar (ADR-0013, no exemption). It owns no table and no SQL. Only `internal/directory/inventory` (via a new `inventory.Explorer` port) calls `CompileTree`. | ADR-0003 rule 6: the SQL owner is `inventory`. |

## 3. API (OpenAPI sketch; api-engineer owns the final contract, ADR-0004)

All three are `GET`, permission `directory.read`, tag `directory-explorer`, under `/api/v1`.
They take no body and no secret, so a query string is safe here (no search text; contrast ADR-0011
rule 15). Rate limit: the platform default.

```yaml
/directory/explorer/roots:
  get:
    operationId: listExplorerRoots
    parameters: [ {name: connection_id, in: query, schema: {type: string, format: uuid}} ]  # optional filter
    responses:
      "200": { schema: ExplorerRoots }
      "403": { description: caller has no directory.read producer }
/directory/explorer/nodes/{objectGuid}:
  get:
    operationId: getExplorerNode
    parameters: [ {name: objectGuid, in: path, schema: {type: string, format: uuid}},
                  {name: connection_id, in: query, schema: {type: string, format: uuid}} ]
    responses: { "200": { schema: ExplorerNode }, "404": {} }
/directory/explorer/nodes/{objectGuid}/children:
  get:
    operationId: listExplorerChildren
    parameters:
      - {name: objectGuid, in: path, schema: {type: string, format: uuid}}
      - {name: connection_id, in: query, schema: {type: string, format: uuid}}
      - {name: view, in: query, schema: {enum: [containers, all], default: containers}}  # tree vs table
      - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 200, default: 100}}
      - {name: cursor, in: query, schema: {type: string, maxLength: 512}}
    responses: { "200": { schema: ExplorerChildren }, "400": {code: cursor_invalid}, "404": {}, "503": {} }
```

```yaml
ExplorerEntry:             # one object; the same shape in tree and table
  objectGuid: uuid
  connectionId: uuid
  parentGuid: uuid | null     # the row's own parent_guid, read in the same statement as the row
  kind: enum [ou, container, user, inetorgperson, group, computer, contact, gmsa, fsp, other]
  objectClass: string
  name: string                # rdn value, else display_name; never a DN
  isContainer: boolean
  hasChildren: boolean | null # containers only: an ADMITTED live child exists (LATERAL … LIMIT 1); null for leaves
  tier0: boolean              # fail closed: unknown is true
  readOnly: boolean           # == tier0 in v1; the console disables write actions on it
  samAccountName, upn: string # table columns, empty when absent
  enabled: boolean | null
  whenChanged: date-time | null
ExplorerRoots:   { items: [ExplorerEntry], asOf: date-time }          # containers only, bounded §4
ExplorerNode:    { node: ExplorerEntry, path: [ExplorerPathItem], asOf: date-time }
ExplorerPathItem: { objectGuid: uuid, name: string }                  # admitted ancestors only, root first
ExplorerChildren:{ items: [ExplorerEntry], nextCursor: string|null, more: boolean, asOf: date-time }
```

`asOf` (per connection; the response carries the oldest) is `inventory.Freshness` over `ReadScope.Connections()` (the only `ReadScope` method a
caller outside `authz`/`reportsql` may use, ADR-0011 rule 10). It is computed inside `internal/directory/inventory`, which E3 adds to the `Connections()` allow-list; `modules/explorer` only receives `asOf` from the port.
No total count is returned. A count is exposed only if it is computed after trimming (LF-39) and is
capped; v1 shows none.

**Path semantics (deep link).** `path` is the maximal run of *admitted live* ancestors ending at the
node's parent, root first, built from `ancestry` joined to `directory_objects` and trimmed in the
same statement. If the parent is not admitted the node is itself a root and `path` is empty. The
console expands the tree along `path` by GUID.

**Ambiguous GUID.** After a cross-domain move the sync expunges the source (DM-16.I1), so one live
row is normal. If a GUID has several live admitted rows (transient), `connection_id` selects;
without it: prefer the row that is `live` whose sibling is not; if two live admitted rows remain, order by
`observed_at` desc then `connection_id` and set `ambiguous: true`. `observed_at` is our sync time, not
AD's, so it is only a tiebreak. The sync should mark the source row `deleted`/`out_of_scope` when the
target domain reports the GUID (backend follow-up).

## 4. Paging bounds and work bound

| Bound | Value | Reason |
| --- | --- | --- |
| page `limit` | default 100, max 200 | table fits one screen of virtualised rows |
| depth walked for `path` | ≤ 128 (the `ancestry` CHECK) | schema bound |
| roots returned | ≤ 500 per call, no cursor; more ⇒ `more: true` and the console shows "refine in Search" | scope roots are few by construction |
| browse depth in one container | unbounded by keyset, but each request examines ≤ **W_e = 5,000** child rows before the scope cut | scoped caller with many excluded siblings (T-0995 class) |
| request time | 2 s statement/context deadline ⇒ `503`, generic | as ADR-0011 rule 13 |

When W_e rows are examined and the page is not full, the response returns what it found with
`more: true` and a cursor that continues from the last *examined* row. It never returns a count.
This reveals to a caller *allowed in* a container that many of its children are hidden from them;
that is the same class as ADR-0011 TM-TB1-T8a and is **accepted pending security-architect review**
(§9, Q4). A caller not admitted to the container gets 404, never this signal.

**Cursor.** Opaque, HMAC-SHA256, using the same codec and key custody as the search cursor (no
second cursor implementation). It binds: parent GUID, `view`, sort position
`(isLeaf, lower(rdn), objectGuid)`, and `ReadScope.Fingerprint()`. Any mismatch is `400
cursor_invalid` and reads nothing.

**Sort.** Containers first, then `lower(rdn)` in `COLLATE "C"`, then `objectGuid`. Chosen for an
index (below), not for locale taste; the console may sort the loaded page client-side by other
columns, and says so.

## 5. Inventory query shape (sketch; the backend ticket fixes the text)

```
children(parent P, view, cursor, limit L):
  base  := directory_objects t
           WHERE t.tenant_id = $tenant AND t.connection_id = $conn AND t.parent_guid = $P
             AND t.state = 'live' AND t.nc_guid IS NOT NULL
             [AND t.kind IN ('ou','container')  if view = containers]
             AND (sortkey(t), t.object_guid) > cursor           -- keyset, index order, no ORDER BY sort node
           LIMIT W_e                                           -- UNSCOPED, work bound
  page  := base WHERE <scopeSQL(t, directory.read)>            -- the one renderer, from planScope/scopeSQL
           LIMIT L + 1
  out   := page + hasChildren via LATERAL (SELECT 1 FROM directory_objects c
             WHERE c.parent_guid = t.object_guid AND c.state='live' AND <scopeSQL(c)> LIMIT 1)
           for containers only
roots(conn?):
  admitted live containers t WHERE <scopeSQL(t)>
     AND ( t.parent_guid IS NULL
           OR EXISTS (SELECT 1 FROM directory_objects p WHERE p.object_guid = t.parent_guid
                      AND p.state = 'live' AND NOT <scopeSQL(p)>) )
  LIMIT 501
node(guid): the row, scopeSQL applied; path by unnest(ancestry) WITH ORDINALITY join, scopeSQL applied per ancestor, contiguous run.
```

- Index (new migration, owner `inventory`): `(tenant_id, connection_id, parent_guid,
  (kind NOT IN ('ou','container')), lower(rdn) COLLATE "C", object_guid) WHERE state='live' AND parent_guid IS NOT NULL`.
  Leads with `tenant_id` (ADR-0011 SE1 posture). The existing `directory_objects_by_parent` cannot give sorted keyset pages.
- **Scope applies before the returned limit and any flag** (LF-39): `more`, `hasChildren` and the cursor
  are functions of admitted rows only, except the W_e examination ceiling discussed in §4.
- Roots on a not-live or missing parent: a row whose parent exists but is not live, or is missing, is
  **not** a root and is unreachable (fail closed; `ancestry_complete = false` rows are out of every
  ancestry scope anyway, DM-16). A diagnostic ("N objects not placed yet") is out of scope.

## 6. Container semantics

*(Reviewed against DM-16/DM-17 and `deleted-object-read-access.md`; the live-AD points are marked
`[AD-REVIEW]` for the ad-expert pass recorded in §9.)*

### 6.1 Move or rename in flight: no stale parent

1. The writer updates `parent_guid`, `ancestry` and `ancestry_complete` in one transaction under the
   per-connection advisory lock (DM-16.I10), and a move rewrites descendants (`rewriteDescendants`,
   T-0988; DirSync does not report children of a moved parent, DM-16 sync I5).
2. Each Explorer request is **one statement**, so a page is a single snapshot: `parentGuid` on every
   row is that row's own column read in that statement, never inferred from the URL.
3. Between two pages a child may move away (it just does not appear on the next page) or move in
   (it appears if it sorts after the cursor). Neither produces a row under the wrong parent. The
   console drops any entry whose `parentGuid` ≠ the requested node (defensive) and refetches that
   node once.
4. While a moved subtree is being repaired its rows have `ancestry_complete = false` and are out of
   every ancestry scope (fail closed), so a scoped technician can see a subtree disappear briefly
   rather than see it under the old parent. An unscoped (`naming_context`/tenant) reader sees it
   under its stored parent. Both are correct as of `asOf`; the footer shows `asOf`.
5. A **rename** changes `rdn` of the renamed row and the display `dn` of its descendants; Explorer
   shows `rdn` only, so a descendant never shows a stale path. Breadcrumb names come from each
   ancestor's own `rdn`.
6. A move changes only the moved object's `parent_guid`, DN and ancestry; its children keep `parent_guid`
   and only `ancestry`/`dn` are rewritten (`rewriteDescendants`). If a move takes an object out of what the
   sync account can read, it disappears: correct, not stale. DirSync is per DC, so `asOf` is per connection.
7. A **root that moved** keeps its scope (DM-35.I1, scope roots are GUIDs); a root that is deleted
   grants nothing (DM-35.I1) and, being not live, is simply absent.

### 6.2 Deleted objects

Only `state = 'live'`. `deleted`, `recycled`, `purged`, `soft_deleted` and `out_of_scope` rows are
never returned. `CN=Deleted Objects` is reachable only with the show-deleted control
([retrieving deleted objects](https://learn.microsoft.com/en-us/windows/win32/ad/retrieving-deleted-objects)),
so Explorer excludes it by its well-known GUID `18E2EA80684F11D2B9AA00C04F79F805`
([WKGUID](https://learn.microsoft.com/en-us/windows/win32/ad/binding-to-well-known-objects-using-wkguid))
in addition to the state filter, because the container's own row could be stored live. The sync must
not store it live; the backend ticket adds a test that a sync with show-deleted on leaves no live row for it.
A deleted OU's children cannot be roots (§5). Browsing deleted objects is the Recycle Bin feature,
not Explorer. (ad-expert review, §9: resolved as above.)

### 6.3 ForeignSecurityPrincipals

`CN=ForeignSecurityPrincipals` is an ordinary `container`; its children are `kind = 'fsp'` leaves
named by their SID string (the `rdn`). They are listed, never resolved to the other forest's object
(DM-17.I4: resolution is a lookup recorded on a membership edge, never a merge) and never shown with
a resolved name. Explorer does not resolve well-known SIDs either (they resolve locally via the well-known SID
table, not the other forest) and shows SID text. FSPs are created lazily, so Explorer never assumes a
foreign group member has an FSP row. An FSP has no `objectGuid` problem: it is keyed like any row.

### 6.4 Containers that are not OUs

`isContainer` is decided on `object_class` (case-insensitive), not on `kind`: `domainDNS`,
`builtinDomain`, `container`, `organizationalUnit`, `lostAndFound`, `msDS-QuotaContainer`,
`infrastructureUpdate`. The 0033 `kind` enum has no value for `domainDNS`/`builtinDomain`; they are
`other`, so a `kind IN ('ou','container')` shortcut would miss them (the tests disagree today:
`ingest_test.go:110` uses container; the backend ticket picks one and fixes it). `groupPolicyContainer`
is not a container. Fallback: any live row with an admitted live child is expandable, so children are
never orphaned (`[UNVERIFIED]` whether other classes hold children). The `view=containers` filter in §5
therefore uses the class list, not `kind`.

### 6.5 Tier 0 (C6)

`tier0` is **not a stored column** (0033 header); the classifiers compute it (T-0326, connector contract
§8.3: C6 containers and C6 OUs holding a DC are classified with a **live** subtree check). Explorer
does no live read, so it cannot recompute that. Rule: `tier0` = the inventory's recorded classifier
result plus customer designations (`inventory.Designations`, DM-16.I8). If neither has a result for
the object or the facts have no as-of time, **`tier0 = true`** (the same fail-closed stance as
`membership.go` `Tier0Either`). Explorer has no write action in v1, so the flag only drives the
disabled-with-reason state in the console (IA principle 6, §8.3). `[Q5: the backend ticket's first task is
to confirm a stored classifier result exists to read; if not, that is a dependency ticket, not a reason to read live]`.

## 7. Screen (frontend-engineer; product-designer owns the layout)

- Route `/directory/explorer[/{ouGuid}]`. Left: tree, each level loaded on expand through
  `listExplorerChildren?view=containers`; right: table through `view=all` of the selected node.
  Selection is in the URL as the GUID. A deep link calls `getExplorerNode`, expands along `path`, and
  shows 404 as the standard "not found or not in your scope" state (one wording for both).
- Roots: one group per connection (domain), showing the domain's display name; never a DN.
- Table: name, type, sam, enabled, tier0 chip, changed; virtualised; "Load more" using `nextCursor`;
  when `more` is true and the page is short the row reads "More objects may follow, keep scrolling".
- States all real (no fake data, no dead buttons): loading, empty OU, empty scope ("No directory
  objects in your scope"), error with retry, stale (`asOf` older than the staleness threshold from the
  freshness footer), 503 ("Directory is busy, try again").
- Tier-0 rows show the chip and no action; there are no actions on this screen at all in v1.
- Keyboard: tree follows the ARIA tree pattern (arrow keys, `*`, type-ahead by name); table follows the
  design-system data table. Accessibility is checked by qa-verifier.

## 8. Platform matrix

| Capability | Windows server | Linux server | Browser | Source of the data |
| --- | --- | --- | --- | --- |
| Roots, node, children, table | yes | yes | the console's supported set (ADR-0001) | Postgres inventory, filled by the sync from any AD (Windows DC or Samba AD) |
| Tier-0 flag | yes | yes | — | inventory classifier result, no live read |
| Live re-read of a container | **none, by design** | **none** | — | — |

No asymmetry: Explorer runs inside the server process and Postgres on both OSes, and is independent of
the DC agent (so it works without the DC agent installed). `[LAB: Windows]` for the container
semantics in §6 (FSP, Deleted Objects, C6 class list); Samba AD in CI is sufficient for tree and trim
tests, and cannot prove Windows-only classes (stated, not hidden).

## 9. Review and open questions

- **ad-expert review (done 2026-11-14, medium confidence, no lab run; sources to be re-checked):** Q1, Q2, Q3 and
  the FSP and move wording are corrected in §3 and §6. Live-lab confirmation stays `[LAB: Windows]`.
- **security-architect:** Q4 the W_e partial-page signal; hidden-sibling count leaks; the 404-for-hidden rule;
  `tier0` fail-closed rule. Explorer is read-only and adds no credential or network surface, so no new
  threat-model row is expected beyond a pointer to TM-TB1-T8a.
- Q5 above (stored classifier result).
- One-level scopes (`ou_one_level`): if the renderer admits the anchor OU's children but not the OU, the
  tree has no container to hang them on. v1 shows only admitted containers as roots and, for a scope that
  admits objects but no containers, the empty-scope-with-Search hint. The backend ticket must prove which
  of the two the renderer does for `ou_one_level` and report it back.

## 10. Fitness expectation: `fitness-explorer` (in `make ci`; owner devops-engineer with test-engineer)

| ID | Fails the build when |
| --- | --- |
| EX1 | any package other than `internal/directory/inventory` calls `reportsql.CompileTree`; `modules/explorer` contains SQL, calls `ReadScope.Admits`/`.Terms`/`.Token`, or defines a second scope function (go/types: exported `reportsql` funcs reaching `planScope`/`scopeSQL` are exactly `Compile`, `CompileCount`, `CompileSearch`, `CompileTree`; definitions count one each; no scope fragment emitted outside them); inventory Explorer files or `modules/explorer` hold SQL naming `ancestry`, `parent_guid` or `directory_objects`; `inventory.Explorer` or its result types expose ancestry or an unadmitted ancestor GUID (ADR-0011 E3) |
| EX2 | the oracle property test fails: for random forests and scopes (subtree, one-level, naming context, exclusions) a walk from `roots` through `children` reaches exactly the live, admitted, container-reachable objects `AuthorizeRead` admits, and `view=all` pages union to the admitted children, with no duplicates and none missing |
| EX3 | the OpenAPI Explorer schemas contain a `dn` property, a non-uuid path identifier, or a cursor that decodes to a DN |
| EX4 | the move-in-flight test fails: a move between pages 1 and 2 yields a row under the wrong parent, a child under both parents, or a descendant displaying a stale name path; after repair the subtree is under the new parent only |
| EX5 | a `deleted`/`recycled`/`purged`/`soft_deleted`/`out_of_scope` row, an Entra row, or an orphan (parent not live or missing) is ever returned or becomes a root |
| EX6 | the plan test fails: `EXPLAIN` of children/roots/node shows a Seq Scan on `directory_objects`, an index not led by `tenant_id`, or rows examined > W_e + L + 1 with H hidden siblings in {0, W_e−10, W_e+10, 20,000} |
| EX7 | an object with no classifier result or no as-of is returned with `tier0 = false` |
| EX8 | a hidden GUID and a nonexistent GUID answer different status, body or headers |
| EX9 | `modules/explorer` or the inventory explorer files import `internal/directory/client`, `internal/connector/…` or an LDAP package (depguard) |

## 11. Ticket cuts (all under E-007; created with this spec)

| Ticket | Owner | Content |
| --- | --- | --- |
| T-2086 | solution-architect | ADR-0011 amendment E3: SE1 widens to `CompileTree`; one renderer, three statements (search, report, tree) |
| T-2087 | api-engineer | OpenAPI for the three operations, schemas, generated client, contract tests (EX3) |
| T-2088 | reporting-engineer | `reportsql.CompileTree` over the same `planScope`/`scopeSQL`, `sqlconst`/RP1 apply, security-architect reviews (EX1, EX6 parts) |
| T-2089 | backend-engineer | migration (index), `inventory.Explorer` port, `modules/explorer` and its registrar wiring, cursor, Q5 and one-level answers, move-in-flight and deleted handling (EX2, EX4, EX5, EX7, EX8) |
| T-2090 | frontend-engineer | the screen of §7 over the generated client, all states, keyboard and a11y, no fake data |
| T-2091 | devops-engineer | `fitness-explorer` EX1–EX9 in `make ci`; test-engineer supplies the oracle generator and the Samba AD fixtures |
