---
name: search-scope-lessons
description: T-0875 search trimming - RP2 allows only authz/reportsql to read Terms, wire GUID order vs ObjectID, clienttest fake directory
metadata:
  type: feedback
---

- RP2 (tools/fitness/reports) bans `ReadScope.Terms/.Token` outside authz and reportsql. A consumer that needs terms (search) gets a method ON the scope in authz (`Admits`, `SearchRoots`), not the terms.
- `authz.ObjectID` is AD octet order; wire `connectorv1.Guid` is RFC/text order. Converting an ObjectID to a SearchRoot needs the first three fields swapped back (`wireGUID` in client/usersearch.go).
- `clienttest.Directory` (client/clienttest) is an in-memory tree that is both ConnectorSource (ScopedSearch by roots/depth/substring) and Reads; reuse it for any search/ancestry test instead of a new fake.
- Ancestry for search comes from live container reads (memoised, budget), not inventory: `ancestry_complete` (P2) does not exist yet. Revisit when P2 lands if reads become a cost.
- Compose has no ReadScopes producer yet (T-0916/T-0987): `buildDirectory(..., nil)` => production search is 403 by design. Compose tests use a `consoleScopes` fake.
- `go test` over rbac+compose+fitness together exceeds the 120 s tool timeout: run it in the background and Monitor.
