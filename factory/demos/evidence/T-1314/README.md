# T-1314 spike: the fuzzy probe under FORCE RLS

This is the evidence behind ADR-0011 revision 3, §3a. It was run on 2026-11-02 by
solution-architect.

**Setup**
- Scratch `postgres:16-alpine` 16.15, limited to 4 CPU and 8 GB.
- Two tenants, each holding 416,000 fuzzy-kind keys. The keys are synthetic names built from
  50 syllables, so their trigram lists are longer than real names would give.
- `ENABLE` and `FORCE` RLS with the ADR-0002 policy, queried as a non-owner `NOBYPASSRLS` role.
- `t = 0.5`, `work_mem` 16 MB, warm cache.
- The SQL is in `fuzzy-posting-spike-pg16.sql` (the setup and the query scripts q3–q7, in order).

**Findings**
1. **The catalogue.** No operator with similarity semantics is leakproof in any GIN, GiST or SP-GiST
   operator class. The only leakproof operator in `gin_trgm_ops` and `gist_trgm_ops` is text `=`.
   B-tree equality on text, int4 and uuid is leakproof.
2. **Today's route.** `<%` under RLS is a Parallel Seq Scan and takes 860–940 ms.
3. **GIN with RLS bypassed** (as superuser, standing in for option c): 1–120 ms. It reads the other
   tenant's postings: for "johanson", 676 of the 1,234 rows rechecked belonged to the other tenant.
4. **A `NOLOGIN NOBYPASSRLS` role with a `USING (true)` policy** gets the planner to use the GIN, so
   option c3 is feasible. It is rejected in the ADR, which gives the reasons.
5. **Postings for all five fuzzy kinds.** The table is a B-tree on `(tenant_id, trgm, key_id)`.
   - 14.8 M rows for both tenants, about 1 GB per tenant.
   - The plan is an Index Only Scan with `tenant_id` and `trgm = ANY` in its `Index Cond`.
   - Queries take 12–330 ms.
6. **Postings for kinds `name` and `sam` only:**
   - 2.0 M rows and 277 MB for one tenant;
   - built in 37 s in bulk;
   - 7–105 ms per query warm (one cold first run took 739 ms).
7. **Pigeonhole variant** (read only the rarest lists): exact, but 4–810 ms, so it is not the default.
8. **Correctness.** Every posting route returned exactly the oracle's matches for the five queries
   ("skrorsors10", "pryia ramn", "johanson", "mullerberger", "raman"). The oracle is `$q <% key` over
   every key, with no index.

The production proof is T-1335: the AC3 oracle property test, the AC4 plan test, the AC5 two-tenant
test, and the AC6 budget on the T-1102 seed, on PostgreSQL 16 and 18.
