---
title: "ADR-0011: Universal search runs over the inventory with pg_trgm, and is trimmed in the same SQL statement by the one ReadScope renderer in store/reportsql"
date: 2026-10-31
updated: 2026-11-02
status: ratified
ratified_on: 2026-10-31
ratified_by: factory-director
decision: D-0014
owner: heramb
author: solution-architect
kind: technical
ticket: T-1093 (revision 3: T-1314)
fitness: fitness-search SE1–SE5 (in make ci) and SE6 (nightly); T-1126 builds it. Not yet in CI, so not `accepted`
---

# ADR-0011: Universal search runs over the inventory with pg_trgm, and is trimmed in the same SQL statement by the one ReadScope renderer in `store/reportsql`

**Status:** ratified 2026-10-31 by factory-director (notice D-0014, T-1093 review). security-architect
confirmed rules 12, 13 and 16 in the re-review. `accepted` when `fitness-search` SE1–SE5 run green
in `make ci` and SE6 has passed once in the nightly job (T-1126).

**Revision 2 (2026-10-31, after the T-1093 review).** These are the changes in this revision:
- **M1:** rule 7 now case-folds before the fold table.
- **M2, M3 and M4:** rules 12 and 13 replace the silent candidate cap with a work ceiling W. The
  scope is applied before every limit, a ceiling hit is a refine state that does not depend on the
  caller, and the unscoped stages are named.
- **M5:** rule 7 refuses input after NFKC. Rule 9 gates the BitLocker key-ID kind on the BitLocker
  permission. Rule 15 keeps search text out of URLs and logs.
- **M6:** rule 16 gates multi-tenant databases on a tenant-isolated trigram index.
- **M7:** SE1 and SE2 close the view, function and trigram-operator bypasses.
- The review's nits are in rules 4, 8, 12 and 13, SE1, SE4 and SE5.

**Revision 3 (2026-11-02, T-1314; proposed until the T-1314 review by factory-director and
security-architect).** Under `FORCE` row security the trigram GIN is never used, because `pg_trgm`'s
operators are not leakproof. The fuzzy probe was a sequential scan, and it was the whole of the M2a
latency miss (T-1102). These are the changes in this revision:
- **New rule 5a (§3a):** fuzzy candidates come from a tenant-led B-tree of trigram postings,
  `inventory_search_trigrams`, read under RLS and rechecked with `<%`. The GIN index is dropped.
- **Rule 5:** the key table gains `key_id`, and its GIN index is replaced by rule 5a.
- **Rules 8 and 9:** the fuzzy-eligible kinds are `name` and `sam`. `name_word`, `upn` and `mail`
  keep exact and prefix matching.
- **Rules 12 and 13:** the fuzzy stage and its rows-examined bound are restated.
- **Rule 16:** this revision closes it by construction. T-1136 is superseded by T-1332.
- **SE1, SE2 and SE5:** they now cover the posting table, its one trigger function and the new plan
  shape.
- **Consequences, follow-on work and revisit triggers** are updated to match.
**Kind:** technical. There is no CEO fork: price, packaging, deployment and platform strategy do not
change. The one customer-visible effect is that a customer-supplied PostgreSQL must have the contrib
extensions installed, and ADR-0001 already allows that kind of prerequisite.
**Deciders:** solution-architect · **Ticket:** T-1093 · **Parity / scope refs:** ADM-001, ADM-003;
MASTER-SPECIFICATION-PRD §8.2 (M2a); roadmap E2.1.
**Builds on:**
- ADR-0001 rule 3 (PostgreSQL is the only stateful service; PostgreSQL 18 is bundled and 16 or later may be customer-supplied);
- ADR-0002 (tenancy: RLS + `FORCE`, tenant-led keys);
- ADR-0003 (modules reach each other through ports only);
- ADR-0010 and [modules/reports.md §4](../architecture/modules/reports.md) (the one producer, the one renderer, RP2, RP6);
- safe-primitives P5 (rule 4 LIKE patterns, rule 7 text, SQL-22 timeouts);
- licence register rows from T-1092.

## Context

**The promise.** M2a promises universal directory search with fuzzy matching, under 200 ms over
50,000 objects, behind a Ctrl+K palette (MASTER-SPECIFICATION-PRD §8.2; IA
[§5](../../product/design-system/information-architecture.md)). The IA already fixes three things.
Search "runs over the inventory index and is trimmed by RBAC on the server … never a live LDAP query
per keystroke" (IA §5.2). Results rank as exact identifier, then prefix, then fuzzy (IA §5.3). Group
counts are "in your scope" (IA §5.3).

**What exists today.** Search is something else.
- `GET /directory/users` (`searchDirectoryUsers`, T-0668/T-0680) calls `client.UserSearch`
  (`internal/directory/client/usersearch.go`). That client runs a contains-filter `ScopedSearch`
  over LDAPS against one connection.
- T-0875 trims the results this way: `ReadScope.SearchRoots` gives the base DNs, and each entry is
  then decided in memory by `ReadScope.Admits` over a parent chain read live from the DC (up to 2,000
  container reads) ([modules/reports.md §4.7](../architecture/modules/reports.md)).
- LDAP has no typo-tolerant matching. AD's Ambiguous Name Resolution is prefix-only
  ([MS Learn: ANR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1a9177f4-0272-4ab8-aa22-3c3eafd39e4b)).
- Each keystroke costs a DC round trip per connection.
- T-0995 records that the entries the scope rejects are read without any bound.

So the live path can deliver neither fuzzy matching nor the 200 ms budget, and T-1090 found that no
ADR covers a search index.

**The inventory is the source of record.** `directory_objects` (migration 0033 and later) is keyed
by `(tenant_id, connection_id, object_guid)` and carries the scope anchor columns:
`connection_id`, `nc_guid`, `object_guid`, `parent_guid`, `ancestry` (GIN-indexed, 0061) and
`ancestry_complete` (0059, kept current on OU moves by T-0948). Those are the columns the reports
renderer already trims by, and RP6 proves that renderer equal to the per-target oracle
`authz.Evaluator.AuthorizeRead`.

**What makes the decision non-obvious.** The only code that turns a `ReadScope` into SQL is
unexported, inside `store/reportsql` (`scope.go`: `planScope`, `scopeSQL`). FF-SP2 `sqlconst` with RP1
allows SQL text only as a constant or as a `reportsql.CompiledSQL`. That leaves search three
choices:
1. use the reports renderer;
2. write a second renderer;
3. trim after the query with `Admits`, which is the second renderer we already have, in Go.

m2-plan decision 4 says search and reports trim by the same rule from one producer. LF-39 says
counts and pages come after trimming. T-0995 says the work per query must be bounded without
revealing how much was hidden.

**Licence and availability (T-1092, register rows in
[open-source-license-register.md](../../business/licensing/open-source-license-register.md)).**
- **`pg_trgm` 1.6** (PostgreSQL Licence, contrib): present and **trusted** on the pinned `postgres:18`
  (18.6) and `postgres:16-alpine` (16.14) images. A plain database owner with no superuser,
  CREATEDB or CREATEROLE can run `CREATE EXTENSION`. GIN and GiST trigram indexes build on both
  versions. Verdict: **usable**.
- **`unaccent`**: usable, with prerequisites. It needs an IMMUTABLE wrapper before it can be indexed
  (`unaccent()` is STABLE), and a REINDEX whenever `unaccent.rules` changes.
- **`fuzzystrmatch`**: no index support, so it can only re-rank.
- **`lithammer/fuzzysearch`, `sahilm/fuzzy`, `agnivade/levenshtein`** (all MIT): usable only for
  small in-memory lists. **Unusable as the search engine.**
- Availability on managed PostgreSQL services is `[UNVERIFIED]` (T-1092 note).

## Decision

We will serve universal directory search from **the inventory**. The match technology is
**PostgreSQL `pg_trgm`** over **search keys normalised in Go**. Each search is **one SQL statement
compiled by `store/reportsql`**. That statement places the existing `ReadScope` renderer inside the
same query as the match, so trimming happens before ranking, counting, limits and pages. The live
LDAP user search is retired.

### 1. Source of truth

1. Universal search answers from `inventory` and only from `inventory`. The source of truth for a
   search hit is the `directory_objects` row and its search keys as of the last sync, and the
   response carries the inventory's freshness `as_of` (IA §5.6 footer, from `inventory.Freshness`,
   T-0949). A search makes no directory call. Live facts are re-read where the IA already requires
   it: the object page re-reads lockout from the PDC emulator (IA §5.8).
2. **`searchDirectoryUsers` (`GET /directory/users`), `client.UserSearch`, `client.NewUserSearch`,
   `modules/directory.UserSearcher` and the composition in `compose/server/directory.go` are
   deleted, not kept as a fallback.** T-1127 deletes them. In the same change it repoints the
   console's `/directory/users?q=` screen (`web/src/modules/directory`) to `directory.search`
   (T-1094) and removes the operation from `api/openapi`. It is the last search build ticket and
   depends on T-1096 and T-1100. When T-1127 lands, `authz.ReadScope.SearchRoots` and
   `ReadScope.Admits` lose their only product caller and are deleted with their tests. The rbac
   property test then keeps `rbac.ReadScopes.For` against `AuthorizeRead` through RP6 alone. T-0995
   is resolved by that deletion, not by a fix to the live path.

   *Why not keep it:*
   - two sources of truth for "who is in my scope" would disagree whenever inventory lags or an OU
     moves;
   - the live path trims with a second renderer;
   - its unbounded scan (T-0995) is the very defect this ADR bounds.

   The connector's `ScopedSearch` RPC itself **stays**: duplicate checks before a create (ADM-012
   and the rest; blueprint §15) and operation planning need the DC's live answer. Only the
   user-search client over it goes.
3. The non-object groups of the overlay (Reports, Pages and settings, Actions; IA §5.2 "Words") are
   **not** served by this index. The console builds them from the catalogues that already exist:
   - the report library list, through the reports API and trimmed by permission;
   - the web Registrar's `palette` and `searchResults` (T-1099);
   - `operation.Catalogue()` for actions, at 2b (blueprint F4).

### 2. Match technology

4. **`pg_trgm` is the fuzzy engine.** The first search migration (T-1095) runs `CREATE EXTENSION IF
   NOT EXISTS pg_trgm` as the migration owner role. This needs no superuser on PostgreSQL 16 or 18,
   because the extension is trusted (T-1092). No other extension is used:
   - **not** `unaccent`: diacritics are folded in Go (rule 7);
   - **not** `fuzzystrmatch`;
   - **not** `btree_gin`.

   `show_trgm` (from this same extension) derives the trigram postings of rule 5a. Using it keeps
   our trigram extraction identical to `pg_trgm`'s own.

   The bundled PostgreSQL 18 image must ship contrib. A customer-supplied server must have the
   contrib package installed (for example the distribution's `postgresql-16-contrib` or equivalent
   `[UNVERIFIED per distribution]`) and must allow `pg_trgm` on managed services
   (`[UNVERIFIED]`). The server's preflight checks `pg_available_extensions` before it migrates and
   refuses to migrate with a message that names the missing package (T-1128). It never fails
   halfway through a migration.

   **Database encoding and ctype.** The ctype decides which letters `pg_trgm` counts as
   alphanumeric, and so which scripts fuzzy matching works for
   ([pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html): "non-alphanumerics" are
   ignored).
   - **Bundled server.** The bundled PostgreSQL 18 creates the product database with `ENCODING
     'UTF8'` and the built-in locale provider, `LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'`.
     That provider has existed since PostgreSQL 17
     ([Locale support](https://www.postgresql.org/docs/17/locale.html)). Its ctype is Unicode-aware
     and does not depend on the operating system's libc or ICU version. Its collation is code-point
     order, which is the same order as the `COLLATE "C"` keys.
   - **Customer-supplied PostgreSQL 16** has no built-in provider. The database must be `UTF8`, and
     any libc `*.UTF-8` ctype will do.
   - **Preflight (T-1128).** It reads `pg_database.encoding`, `datlocprovider` and `datctype`. It
     refuses a database that is not `UTF8`. It warns when the ctype is `C` or `POSIX`: there, fuzzy
     matching still works for every key that rule 7 folds to ASCII, but not for Cyrillic, Greek or
     CJK keys.
   - **Unverified.** Whether `pg_trgm` 1.6 classifies non-ASCII letters through the built-in
     `C.UTF-8` ctype is `[UNVERIFIED]`. T-1095's per-script vectors run on both images and settle it.

### 3. Index shape (owned by `inventory`, built by T-1095)

5. A table `inventory_search_keys` holds the search keys, and `internal/directory/inventory` is its
   only SQL owner (ADR-0003 rule 6).
   - **Columns and key.** `(tenant_id, connection_id, object_guid, key_kind smallint, key text
     COLLATE "C", norm_version smallint, key_id bigint)`. The primary key is the first five of
     these. `key_id` (rev 3) is `GENERATED ALWAYS AS IDENTITY` with `UNIQUE (tenant_id, key_id)`,
     and rule 5a's postings refer to it.
     A foreign key points to `directory_objects (tenant_id, connection_id, object_guid)`. The table
     has RLS with `FORCE` and the one fail-closed policy shape.
   - **Indexes.** A B-tree on `(tenant_id, key_kind, key)` serves exact and prefix matches.
     Fuzzy matches are served by rule 5a's posting table. **The table has no trigram index** (rev 3):
     the partial GIN `inventory_search_keys_fuzzy` from 0069 cannot be used under row security
     (§3a), and T-1332 drops it.
   - **Scope columns are not copied.** The table carries none of the scope anchor columns. The
     search statement joins `directory_objects` and trims there, so OU moves and `ancestry_complete`
     repairs have one place to be right.
   - **Written with the object.** The sync writer writes an object's keys **in the same
     transaction** as its `directory_objects` row, and a rolled-back observation leaves them
     unchanged (T-1095 AC2). Every writer of `dn` (T-0988 rewrites descendants' `dn` on a move)
     rewrites the `dn` keys in that same transaction.
   - **Backfill.** A key row whose `norm_version` is older than `searchkey.Version` is rewritten by
     the backfill job. The backfill is idempotent and reports progress. This is how a change to the
     normaliser reaches stored keys without a REINDEX.
6. **Keys come from an allow-list, never from the generic attribute bag as a whole.** No key is
   derived from a secret attribute (`SecretAttrs`) or from a confidential attribute such as
   `msFVE-RecoveryPassword`. T-1095 AC5 tests this. Keys are values the console already shows (IA
   §5.3), so the index adds no new disclosure. It is trimmed exactly like the objects.

### 3a. The fuzzy probe under row security (revision 3, T-1314)

**What was measured.**
- **Why the GIN is never used.** Under row security, PostgreSQL enforces "conditions from security
  policies … before any user-supplied conditions from the query itself that contain non-leakproof
  functions". Marking a function `LEAKPROOF` "can only be set by the superuser"
  ([CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html)).
  - `pg_trgm`'s `%`, `<%` and `%>` are not leakproof. So with `FORCE` RLS on
    `inventory_search_keys`, they never become index conditions, and the GIN index is never used
    (T-1095, T-1102).
  - The PostgreSQL 16.15 catalogue lists no leakproof operator with similarity semantics in any GIN,
    GiST or SP-GiST operator class. The only leakproof operator in `gin_trgm_ops` and
    `gist_trgm_ops` is text `=` (T-1314 spike, `pg_amop` joined to `pg_proc.proleakproof`).
  - B-tree equality on `text`, `int4` and `uuid` is leakproof, and the policy's own `tenant_id`
    qual is always usable.
- **What it cost at 50,000 objects on PostgreSQL 16** (T-1102 root-cause probe,
  `factory/demos/evidence/T-1102/root-cause-plan-pg16.txt` on `factory/T-1102`):
  - The fuzzy stage is a Parallel Seq Scan with 415.6k rows removed by filter. It takes 372 of the
    389 ms of the handler's statement.
  - The same statement without the fuzzy stage takes 0.9–1.2 ms.
  - `searchkey.Classify` adds the fuzzy class to every query of 3 or more runes. So exact, prefix,
    fuzzy and no-match queries all miss rule 14, and the cost grows linearly with the tenant.

5a. **Fuzzy candidates come from a tenant-led B-tree of trigram postings, read under row security,
    and each candidate is rechecked with `<%`.** `internal/directory/inventory` owns the table, and
    T-1332 builds it.
    - **Table.** `inventory_search_trigrams (tenant_id uuid, trgm text COLLATE "C", key_id bigint)`,
      with `PRIMARY KEY (tenant_id, trgm, key_id)`.
      - It is a tenant table under ADR-0002: RLS `ENABLE` and `FORCE`, the one fail-closed policy,
        registered with `fitness-tenancy`.
      - It carries no key text and no scope columns.
      - It has no foreign key. Rule 5a's trigger is what keeps it equal to the keys, and T-1332 AC2
        tests that.
    - **Postings are a function of the keys, maintained by the database.**
      - One statement-level trigger function, `inventory_search_trigrams_sync`, maintains them. It is
        `SECURITY INVOKER`, uses transition tables and is attached `AFTER INSERT`, `AFTER DELETE` and
        `AFTER UPDATE OF key` on `inventory_search_keys`.
      - It writes one row `(tenant_id, t, key_id)` for each `t` in `show_trgm(key)`, and only for the
        fuzzy-eligible kinds `name` (1) and `sam` (3).
      - It runs as the caller under the same policy (`WITH CHECK`). So the sync writer, the `dn`
        rewrite on an OU move (T-0988), the backfill and deletion all keep the postings right
        without knowing that they exist.
    - **The fuzzy-eligible kinds are `name` and `sam` only** (rule 9).
      - `name_word` is redundant for fuzzy matching: `word_similarity` against the whole `name` key
        already scores its best-matching word extent
        ([pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)).
      - `upn` and `mail` keys carry a domain suffix shared by nearly every key, which multiplies the
        postings and adds nothing to name matching.
      - In the spike, postings for all five kinds came to 7.4 M per 50k-object tenant and took
        12–330 ms. Postings for `name` and `sam` came to 2.0 M (277 MB) and took 7–105 ms.
    - **The probe** (the `m_fuzzy` stage of rule 12, in the `reportsql` search template only):
      1. `Q = show_trgm($q)`, and `n` = the number of trigrams in `Q`. If `n = 0` there is no fuzzy
         class.
      2. **Candidates:** the `key_id`s whose postings hold at least `⌈t · n⌉` of `Q`, where `t` is the
         one bound threshold that the same transaction also sets as
         `pg_trgm.word_similarity_threshold`. This is an Index Only Scan of the posting primary key
         with `Index Cond: tenant_id = … AND trgm = ANY (Q)`.
         - The bound is `pg_trgm`'s own GIN consistency rule for `<%`: the share of the query's
           trigrams present in the key is at least the threshold. So the candidate set is a
           superset of the matches.
         - The template may loosen the bound and never tighten it.
         - That the bound mirrors `pg_trgm` 1.6's source exactly is `[UNVERIFIED]`. T-1332 AC3's
           property test against an index-free `<%` oracle is the proof. The spike agreed with that
           oracle on every query it ran.
      3. **Recheck:** each candidate is looked up in `inventory_search_keys` by `(tenant_id,
         key_id)`, filtered by the call's kind list (rule 9 gating), and kept if `$q <% key`. The
         stage then applies `LIMIT W + 1`. `<%` runs here as an ordinary filter over rows already
         admitted by the policy, so its leakproofness does not matter.
    - **Tenant isolation is kept, and no superuser is needed.**
      - Every read is by the runtime role, on `FORCE`d tables, through the one policy shape.
      - The posting B-tree leads with `tenant_id`, so a tenant's fuzzy scan reads only its own index
        entries. **This closes rule 16.**
      - There is no `SECURITY DEFINER` function, no `BYPASSRLS`, no new role, no cross-tenant policy
        and no hand-written tenant filter.
      - The migration is plain `CREATE TABLE`, `CREATE FUNCTION` (invoker) and `CREATE TRIGGER` by
        the migration owner. `show_trgm` belongs to the trusted extension that rule 4 already
        installs.
    - **No new scope renderer.** The postings and candidates are unscoped stages under rule 12's
      invariant, exactly as `m_fuzzy` was. Trimming still happens only in `hits`, by `scopeSQL`.
    - **The expected plan** (asserted by `Test_search_plan_uses_the_indexes` and SE5, under `FORCE`
      RLS as the runtime role, on PostgreSQL 16 and 18):
      - an Index Only Scan (or Index Scan) using `inventory_search_trigrams_pkey`, whose
        `Index Cond` holds `tenant_id` and `trgm`;
      - an aggregate by `key_id`;
      - an Index Scan of `inventory_search_keys` on `(tenant_id, key_id)` for the recheck;
      - **no Seq Scan** on `inventory_search_keys`, `inventory_search_trigrams` or
        `directory_objects`.

      The test **flips**: it stops pinning the limit (the "planner does not use the GIN" half) and
      asserts this plan. Its RLS-off GIN proof is deleted with the GIN index.
    - **The expected budget.** The fuzzy stage reads the tenant's postings for the query's trigrams,
      plus one key lookup per candidate. Rows examined are bounded by the tenant's own data, never
      another tenant's (rule 13).
      - Target: the handler statement, fuzzy stage included, takes ≤ 130 ms on the T-1102 seed. That
        is rule 14's statement share.
      - T-1332 AC6 re-runs T-1102's root-cause probe to show it. T-1102 then measures the p95.
    - **Levers within this shape,** if T-1332 misses the target. Each keeps the tenant-led B-tree and
      the `<%` recheck, so it needs no new revision, provided T-1332 AC3 and AC5 still hold:
      1. **Read only the rarest lists.** A key holding at least `⌈t · n⌉` of `n` trigrams holds at
         least one of any `n − ⌈t · n⌉ + 1` of them, so the probe can read only the rarest lists. In
         the spike this was exact, but slower for short queries, so it is not the default.
      2. **A per-tenant vocabulary.** The posting unit becomes the distinct normalised fuzzy text,
         which pays when names repeat. It needs orphan collection.
      3. **A transaction-local `work_mem`** for the search transaction.

**Spike** (T-1314, scratch `postgres:16-alpine` 16.15, 4 CPU, 8 GB; two tenants of 416k fuzzy-kind
keys each; synthetic names from 50 syllables, so trigram lists are longer than in real names; `FORCE`
RLS and a non-owner role; warm cache; t = 0.5; SQL in `factory/demos/evidence/T-1314/`):

| Route | Postings per tenant | Size | Query time (5 queries, warm) | Matches equal to the `<%` oracle |
|---|---|---|---|---|
| Today: `<%` under RLS (Parallel Seq Scan) | none | GIN 39 MB, unused | 860–940 ms | yes |
| GIN with RLS bypassed (option c, best case) | none | GIN 39 MB | 1–120 ms; reads the other tenant's posting lists (676 of 1,234 rows rechecked for "johanson") | yes |
| **Postings, kinds `name` and `sam` (chosen)** | **2.0 M** | **277 MB** | **7–105 ms** (one cold first run: 739 ms) | **yes** |
| Postings, all five fuzzy kinds | 7.4 M | about 1 GB | 12–330 ms | yes |
| Postings + pigeonhole on the rarest lists | 7.4 M | about 1 GB | 4–810 ms | yes |

**Options considered for the fuzzy probe**

| Option | Keeps RLS + `FORCE`, no cross-tenant path | What the migration owner needs | Closes rule 16 | Verdict |
|---|---|---|---|---|
| **(a) Tenant-led trigram posting table + `<%` recheck** | Yes | Plain DDL | Yes | **Chosen.** It costs index volume (about 277 MB per 50k objects in the spike) and write amplification on sync, and per query it is 2–8× slower than a GIN with RLS bypassed on the spike's data, with a similar worst case (105 against 120 ms) |
| (b) `LEAKPROOF` wrappers around `pg_trgm`'s operators | Yes | **Superuser** ("can only be set by the superuser", [CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html)) | No | Rejected. The migration owner must never need superuser (ADR-0002, T-1092). A leakproof promise about third-party C code is not ours to make either |
| (c1) `SECURITY DEFINER` candidate function as a `BYPASSRLS` role | No: a function that reads every tenant | **Superuser or a `BYPASSRLS` holder** to create the role ([CREATE ROLE](https://www.postgresql.org/docs/current/sql-createrole.html)) | No | Rejected. ADR-0002 T3 forbids `BYPASSRLS` in the runtime path |
| (c2) `SECURITY DEFINER` function owned by the table owner, with `FORCE` removed | No | Plain DDL | No | Rejected. It breaks ADR-0002's "RLS `ENABLE`d and `FORCE`d on every tenant table" (fitness-tenancy) |
| (c3) `SECURITY DEFINER` function as a `NOLOGIN NOBYPASSRLS` role with a `USING (true)` policy | No: a cross-tenant read policy on a tenant table, and a hand-written `tenant_id` filter inside the function | An installer-created role (`CREATEROLE`) | **No** (the GIN still reads other tenants' posting lists) | Rejected. The spike shows it works: the constant-true policy qual lets the planner use the GIN. But it is a per-keystroke, tenant-scope, cross-tenant read of key text whose only isolation is our `WHERE` clause. ADR-0002 rule 4 admits a `SECURITY DEFINER` reader only when it is column-limited, platform-scope and has one call site, and this is none of those. It is the fastest option, and a bug in it would disclose another tenant's names on SaaS |
| (d) `btree_gin` multi-column GIN `(tenant_id, key gin_trgm_ops)`, or LIST partitions with one GIN each | Yes | Plain DDL (`btree_gin` also needs a register row) | Partly | Rejected. Neither changes leakproofness, so `<%` is still a filter and the probe is still a scan. Both were rule 16 candidates (T-1136) and are superseded |
| (e) GiST `gist_trgm_ops` with `<<->` KNN | Yes | Plain DDL | No | Rejected. Its operators are not leakproof either |
| (f) The match inside the RLS policy (search text in a setting the policy reads) | Yes | Plain DDL | No | Rejected. Policy quals can use the index, but the policy would become per-query and stop being the one fail-closed shape that fitness-tenancy checks |
| (g) Run fuzzy only when exact and prefix return few rows | Yes | Nothing | No | Rejected. It changes how often the scan runs, not its cost: fuzzy1 p95 was 706 ms |
| (h) Accept with a measured budget | Yes | Nothing | No | Ruled out (T-1314). The scan is linear and already 2× over rule 14 at 50k |

### 4. Normalisation (one function, used for keys and for queries)

7. A leaf package `internal/platform/searchkey` holds the normalisation. It imports only the
   standard library and `golang.org/x/text`, which is already in the register. It is the **only**
   code that normalises search text. The writer uses it to build keys and `modules/search` uses it
   to classify and normalise the query, so the two can never drift apart.
   - **Refusals** (P5 rule 7), in this order. The order matters: a check that runs before NFKC can
     be passed with full-width or compatibility forms.
     1. **On the raw bytes:** invalid UTF-8, any NUL, and more than 4 KiB are refused (400). The
        byte cap bounds the work NFKC can be asked to do.
     2. **NFKC.** Every later check and every later step sees only the NFKC form.
     3. **On the NFKC form:**
        - more than 256 runes is refused (400);
        - **the recovery-password shape is refused**, never echoed and never logged (T-1096). The
          shape is: after removing whitespace and every dash (`unicode.Pd`), the text holds a run of
          48 or more decimal digits (`unicode.Nd`). NFKC turns full-width digits into ASCII, and
          `unicode.Nd` also catches other scripts' digits, which NFKC leaves as they are.
     4. Only then are the query's shape (rule 9) and its normalised forms computed.
   - **Name keys and name queries** (`NormName`) go through these steps in order. Case folding comes
     **before** the table, so the table needs lowercase entries only, and an upper-case and a
     lower-case spelling always reach the same key:
     1. NFKC, so full-width letters, ligatures and `ŀ` (to `l·`) fold to their plain forms.
     2. Full Unicode case folding (`cases.Fold`, not the Turkic variant). This turns `ß` and `ẞ`
        into `ss`, and `İ` into `i` followed by U+0307.
     3. NFD, then removal of combining marks (`unicode.Mn`). This removes the U+0307 left by `İ`.
     4. An explicit table for letters that do not decompose, all lowercase: ł→l, đ→d, ø→o, ħ→h,
        ı→i, æ→ae, œ→oe, þ→th. It also deletes U+00B7 (middle dot), so `col·lecció` becomes
        `colleccio`. This covers the Łódź→lodz case that T-1092 showed `pg_trgm` alone cannot fold.
     5. NFC.
     6. Punctuation `, . - ' _ ( )` becomes a space, runs of whitespace collapse to one space, and
        the result is trimmed.

     **Required vectors** (T-1095 and SE4). These were checked against Python's NFKC, `casefold`
     and NFD, which implement the same Unicode operations; the Go implementation must reproduce
     them.

     | Inputs | Key |
     |---|---|
     | `Łódź`, `łódź`, `ŁÓDŹ` | `lodz` |
     | `Øster`, `øster` | `oster` |
     | `İstanbul`, `ISTANBUL`, `istanbul` | `istanbul` |
     | `Straße`, `STRASSE` | `strasse` |
     | `ẞ` | `ss` |
     | `Æsir` | `aesir` |
     | `Þór` | `thor` |
     | `Đorđe` | `dorde` |
     | `Ｐｒｉｙａ` | `priya` |
     | `ﬁnn` | `finn` |
   - **Identifier keys and queries** (`NormIdent`) are NFKC, then `cases.Fold`, then trimmed. Their
     punctuation (`. @ \ $ - =` and the rest) is kept.
   - **"Raman, Priya".** A name query that holds exactly one comma is also tried with its two sides
     swapped ("priya raman") for exact and prefix matching. Fuzzy matching needs no swap: `pg_trgm`
     pads and extracts trigrams per word, so word order hardly changes similarity
     ([pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)).
   - **Scripts with no Latin fold** (Cyrillic, Greek, CJK) keep their letters. Exact and prefix
     matching works for them. Fuzzy matching depends on `pg_trgm` treating those letters as
     alphanumeric under the database's ctype `[UNVERIFIED for CJK under a C ctype]`. T-1095 carries
     one vector per script.
   - `searchkey.Version` is bumped whenever any of these rules changes (rule 5, backfill).

### 5. Match classes and identifier shapes

8. **Classes,** best first. An object appears once, in its best class.

   | Class | Predicate (all values are bound parameters) | Index |
   |---|---|---|
   | `exact` | The query parses as an identifier shape (below), and its `NormIdent` form equals a key of that kind | B-tree equality |
   | `prefix` | A name or identifier key starts with the query: `key >= $p AND key < $p_hi` over the `COLLATE "C"` column, where `$p_hi` is the query with its last code point incremented, computed by `searchkey.PrefixUpper`. For a one-word query this also includes per-word name keys (`name_word`), so "pri" finds "Priya Raman" | B-tree range |
   | `fuzzy` | Only when the normalised query has at least 3 runes: `$q <% key` (`pg_trgm` word similarity) over the fuzzy-eligible kinds `name` and `sam` (rev 3). The threshold is set per transaction through the static statement `SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)`, and the same bound value sets rule 5a's candidate bound. It is `[PROPOSED]` 0.5 and T-1095/T-1102 tune it against the 'Pryia Ramn' vector | Rule 5a: B-tree on `inventory_search_trigrams (tenant_id, trgm, key_id)` for candidates, then a `(tenant_id, key_id)` lookup and a `<%` recheck |

   **`PrefixUpper` edges.** The keys are compared under `COLLATE "C"` in a UTF8 database, and there
   byte order is code-point order. `PrefixUpper` increments the last code point:
   - U+D7FF goes to U+E000, skipping the surrogates, which are not valid in UTF-8;
   - U+10FFFF cannot be incremented, so it is dropped and the code point before it is incremented;
   - a query made only of U+10FFFF has no upper bound, and the predicate becomes `key >= $p`.

   T-1095 unit-tests all three cases, and an ASCII case.

   **No search SQL uses `LIKE`, `ILIKE`, `SIMILAR TO` or a POSIX regex.** Prefix is the bound range
   above, so no user text ever becomes a pattern. The trigram operators and functions appear only in
   the `reportsql` search template (SE2). Within a class, results order like this:
   1. live before deleted;
   2. enabled before disabled (IA §5.3);
   3. for `prefix`, a key equal to the whole query first, then the shorter key;
   4. for `fuzzy`, higher `word_similarity` first;
   5. then the normalised display name;
   6. then `object_guid`, so the order is total and stable.

   The IA's "the user's recent objects" step is **not** in the 2a server ranking. It needs a
   per-account recents store, which T-1130 (P3) adds. Until then the palette shows no recents
   rather than invented ones (CLAUDE.md rule 6).

9. **Identifier shapes the inventory serves at 2a.** The source is the 2a sync set, reports-2a D1–D3
   ([reports-2a §7](../../product/specs/reports-2a.md)), plus the columns of `directory_objects`.

   | IA §5.2 shape | Served at 2a from | Key kinds (class) | Not served at 2a → follow-up |
   |---|---|---|---|
   | Free text | `display_name`; `rdn` (cn) | `name` (prefix, fuzzy), `name_word` (prefix; rev 3: no longer fuzzy, §3a) | `givenName` + `sn` in both orders, `title`, `department` → **T-1129** (until then "Raman, Priya" matches a displayName or cn written in either order, through the comma swap and trigram order-insensitivity) |
   | `sam`, `DOMAIN\sam`, `sam@dnsdomain` | `sam_account_name`; computers also without the trailing `$` | `sam` (exact, prefix, fuzzy) | The `DOMAIN\` and `@dnsdomain` parts narrow to the connection whose NetBIOS or DNS domain name matches, **if** the connection record holds that name (T-1095 confirms). Otherwise the domain part is dropped and `sam` matches in every connection. It is never an error |
   | `x@y` | `upn`; contact `mail` (D3) | `upn`, `mail` (exact, prefix; rev 3: no longer fuzzy, §3a. A misspelt address finds its object through the `name` or `sam` key) | user `mail`, `proxyAddresses`, `mailNickname` → **T-1129** |
   | Digits | none | | `employeeID`, `employeeNumber` → **T-1129**. Until then digits are matched as free text |
   | `S-1-5-…` | `sid` (canonical string form) | `sid` (exact) | `sIDHistory` → **T-1129** |
   | GUID, with or without braces | `object_guid`; `consistency_guid` (as a GUID and as base64) | `guid`, `consistency_guid` (exact) | The Entra object ID is indexed, but Entra objects are **admitted by no 2a scope kind**: they carry no `nc_guid`, and the 2a kinds are AD-only. They become findable when an Entra read-scope root kind exists → **T-1131** |
   | `CN=…,DC=…` | `dn` snapshot | `dn` (exact) | Descendants of a moved OU have stale `dn` keys until T-0988 lands. Rule 5 requires T-0988 to rewrite their keys too |
   | Host name or FQDN | computer `rdn`/`sam` without `$`; `dNSHostName` | `name`, `dns_host` (exact, prefix) | `servicePrincipalName` values → **T-1129** |
   | 8 hex characters (BitLocker key ID) | none | | `msFVE-RecoveryInformation` child CN only, **never** the recovery password; Entra-escrowed keys come from Graph → **T-1129**. **Gated by the BitLocker read permission, not `directory.read`** (below) |
   | 48-digit recovery password | **refused**: 400, never echoed or logged (T-1096 AC5). It is recognised on the NFKC form (rule 7), so full-width digits and other scripts' digits are refused too. The browser also refuses it (IA §5.2) and never puts it in a URL | | |

   The shape is recognised in `searchkey.Classify` and is never passed through to SQL as a string
   to interpret. A recognised shape adds the `exact` branch. Name matching (`prefix`, `fuzzy`)
   still runs, so `jsmith` also prefix-matches "jsmith2".

   **Gated key kinds.** Every key kind declares the permission it is read under. Every kind in the
   2a set is read under `directory.read`.
   - **The BitLocker key-ID kind (T-1129)** is read under the BitLocker key-read permission. That is
     the permission behind threat-model §6.3 R11; the BitLocker feature names it in the catalogue,
     and until it does, the kind is not indexed. A key ID tells whoever can search it that a recovery
     key exists for that computer, so `directory.read` alone must never admit one.
   - **Scope per kind.** `SearchQuery` names each kind's permission. The caller passes one
     `ReadScope` per permission, each produced by `rbac.ReadScopes.For` for that permission (rule
     10). `CompileSearch` renders each kind's rows against its own scope with the same
     `scopeSQL`.
   - **No scope means no rows.** A kind whose permission has no scope in the call compiles to
     `FALSE`.

   SE3 covers a world in which a technician holds `directory.read` but not the BitLocker
   permission. In that world the technician gets no key-ID hit, and that technician's counts are
   the same as in a world with no key-ID keys at all.

### 6. Trimming: one producer, one renderer, in the statement

10. **Producer.** The caller's scope is `rbac.ReadScopes.For(…, directory.read)`, reached through
    the composed port (T-0987). A gated kind (rule 9) also needs `rbac.ReadScopes.For(…, <its
    permission>)`. `rbac.ReadScopes.For` is the only producer: RP2 already confines `NewReadScope` to
    `rbac` and `authz`. Every error and every empty scope answers nothing: `ErrOwnerDead`,
    `ErrTokenRefused`, `ErrUnsupportedChain`, no producer (403), `Empty`. Outside `authz` and
    `reportsql`, the only method of the scope a search caller may use is `ReadScope.Connections()`,
    and only to choose which connections' freshness `as_of` to show. Reports' run job does the same
    today (SE1).
11. **Renderer: search reuses the reports renderer through one new exported entry point, and uses
    no per-result `Admits`.** `store/reportsql` gains
    `CompileSearch(src SearchSource, q SearchQuery, scopes SearchScopes) (Query, error)`, where
    `SearchScopes` maps each permission named by the query's kinds to the `authz.ReadScope` the
    producer gave for it. At 2a that is `directory.read` only.
    - `SearchSource` is registered by `inventory`, as datasets are. It names the key table and the
      `directory_objects` anchor columns, pre-quoted once at registration.
    - `SearchQuery` is a typed value: normalised text, class set, kinds, type facet, per-group
      limit, verified cursor, work ceiling W (rule 13). It holds no SQL fragments.
    - `CompileSearch` returns the existing `reportsql.Query`, so RP1 and `sqlconst` apply unchanged.
    - The statement is a fixed template inside `reportsql`. Its scope position is filled by the
      existing `planScope` and `scopeSQL` over the `directory_objects` anchor, the same functions
      RP6 proves. So `ancestry_complete`, the fail-closed rules, the 512-term cap
      (`ErrScopeTooLarge`) and `ScopeReasons` all carry over unchanged.
    - Only `internal/directory/inventory` calls `CompileSearch` (SE1). `modules/search` reaches it
      through the port `inventory.Search(ctx, tx, tenant, scopes, q)`, composed in
      `compose/server`. The port **takes the scope and returns trimmed hits**. It never returns
      ancestry for the caller to trim with: this amends T-1095 AC3.
12. **The scope comes before every limit. Counts, limits and pages come after trimming (LF-39).**
    The statement has this shape (sketch; T-1095 fixes the text):

    ```
    m_c   := for each class c in (exact, prefix, fuzzy): the key rows that match c,     -- UNSCOPED
             read in the index's own order with no ORDER BY:
               exact, prefix: B-tree on (tenant_id, key_kind, key), one equality or range scan per kind;
               fuzzy:         rule 5a: posting B-tree (tenant_id, trgm = ANY(show_trgm($q))),
                              key_ids holding >= ceil(t*n) of the n query trigrams,
                              then key lookup by (tenant_id, key_id) and $q <% key;
             LIMIT $W + 1
    ceil  := the best class c whose m_c holds W + 1 rows, or none                       -- UNSCOPED; caller-independent
    best  := DISTINCT ON (connection_id, object_guid) over m_c, for the classes ranked above ceil only
                                                                                        -- UNSCOPED
    hits  := best JOIN directory_objects t USING (tenant_id, connection_id, object_guid)
             WHERE <scope(t, kind's permission) from scopeSQL>  AND  <type facet, bound>  -- ADMITTED rows only
    out   := over hits only: the full rank tuple (rule 8), row_number() per group <= $group_limit + 1,
             count(*) per group, keyset cursor; plus the one boolean ceiling_hit := (ceil is not none)
    ```

    - **The unscoped-stage invariant (M4).** `m_c`, `ceil` and `best` read rows that the scope has
      not yet trimmed. No aggregate, flag, cursor, ordering or limit in the output reads them. The
      output reads only `hits`, with one exception: `ceiling_hit`. That boolean is a function of the
      tenant, the normalised query and which gated kinds' permissions the caller holds at all. A
      gated kind (rule 9) enters `m_c` only when the call carries a non-empty scope for its
      permission. The boolean never depends on the extent of any scope, so two callers holding the
      same permissions get the same value for the same query, however differently their scopes are
      drawn.
    - **Ranking only after the cut.** The rank tuple of rule 8 (live, enabled, whole-query-equal,
      shorter key, similarity, display name, `object_guid`) is computed only over `hits`. That is a
      set of at most 3(W + 1) admitted rows. It is never used to choose which matched rows to read.
      Because a class over the ceiling is withheld whole, and never cut to a partial set, the order
      in which `m_c` was read cannot change any answer.
    - **Exact answers below the ceiling.** When no class hits the ceiling, the hits, the group counts
      and the `more` flags are exactly the oracle's: objects that match the query and that
      `AuthorizeRead` admits. They are not an approximation and they are not a top-K. No number in a
      response is ever computed from rows the scope rejects.
    - **The refine state (a ceiling hit).** Classes are taken best first.
      - The first class with more than W matching key rows is the ceiling class. It and every class
        below it are **withheld**.
      - Classes ranked above it are still answered exactly. In practice that is `exact`, so a
        technician who typed `jsmith` still sees `jsmith`.
      - The response carries `refine: true`, **no counts for any group**, no `more` flags and no
        cursor. The console shows "Keep typing to narrow the search" (T-1094 and T-1100 own the
        copy).
      - Every caller with the same permissions gets this state for the same tenant and query,
        whatever their scope. It is never a zero-result answer that a hidden OU could cause.
    - **Counts need at least 3 runes.** A group's count is shown only when the normalised query has
      at least 3 runes and `refine` is false. For one- and two-rune queries a group shows its first
      results and "Show all" with no number.
    - **`more`** is true only when the admitted hits exceed the group limit.
    - **"Show all"** (`/search`, IA §5.7) pages with a keyset cursor over the rank tuple of admitted
      hits, 50 per page, and stops at 1,000 admitted hits with "refine your search". That stop
      depends only on admitted rows.
    - **The cursor is opaque and bound to its query.** It carries the rank tuple of the last admitted
      hit and an HMAC-SHA256 under a server key. The MAC covers that tuple, the normalised query, the
      class set, the type facet and `ReadScope.Fingerprint()` of every scope passed. A cursor
      presented with a different query, facet or scope, or with a bad MAC, is 400, and the request
      reads nothing.
    - **No frozen pages.** Search is not a frozen report run, so ADR-0010 does not apply. A page
      re-runs the statement, so pages may shift if the inventory changes in between.
13. **The work per query is bounded, whatever the scope's shape (T-0995 class).** The values are
    `[PROPOSED]`, and T-1102 measures and sets them:
    - **One statement.** At most one search statement per request, plus at most one batched metadata
      read keyed by the admitted GUIDs (T-1097). There are no per-hit queries.
    - **The work ceiling W** (`MaxSearchMatches`). `[PROPOSED]` 10,000 matched key rows per class.
      T-1102 sets it to the largest value at which a ceiling-sized class still meets rule 14's p95.
      W is a property of the tenant's data. It is not a cap on what a caller sees: below W every
      answer is complete, and above W every caller gets the refine state.
    - **Exact and prefix: rows examined ≤ W + 1 per class.** The B-tree is tenant-led and is read in
      key order with `LIMIT W + 1`. The work is independent of the scope, of how much the scope
      hides, and of other tenants.
    - **Fuzzy: rows returned ≤ W + 1 per class, but rows examined are bounded by the tenant's
      postings for the query's trigrams, plus one key lookup per candidate, and by the timeout**
      (rev 3, rule 5a). This is stated plainly. The candidate step reads the posting lists of the
      query's trigrams in full, because a candidate's count is known only after every list is read.
      `LIMIT W + 1` stops the recheck, but candidates that fail it are not counted against it.
      - The posting B-tree leads with `tenant_id`, so the bound is **the tenant's own postings**,
        in every deployment profile. No tenant's work depends on another tenant's data.
      - T-1332 and T-1102 measure it at 50,000 objects.
    - **After the cut.** At most 3(W + 1) rows are joined to `directory_objects` by primary key,
      evaluated against the scope and sorted.
    - **Other existing bounds:**
      - at most 50 per group;
      - at most 512 scope terms (`ErrScopeTooLarge`);
      - `fuzzy` only from 3 runes;
      - the statement's plan must use the key B-tree, the posting B-tree and the `(tenant_id,
        key_id)` index, with no sequential scan on the key table, the posting table or
        `directory_objects` (SE5).
    - **Timeout.** The store's per-transaction `statement_timeout` (SQL-22) is 2 s for search, as a
      safety net. A timeout gives every caller a generic 503 "search unavailable" with a trace ID and
      no count.
    - **Rate limit.** The platform rate limiter answers 429 (T-1094 AC4).

    **What an answer may reveal.** Below the ceiling, a caller learns exactly the admitted matches,
    and nothing that depends on hidden rows. Two things are left over: the ceiling state, and the
    response time, which grows with the matching key and posting volume of the whole tenant, never
    of another tenant (rule 5a). The ceiling reveals "the tenant holds many keys matching this text",
    the same to every caller, and never which objects or where. Timing can, in principle and only with
    many rate-limited samples, confirm that a named object exists: an exact match on a hidden object
    adds a few key rows, one primary-key join and one scope check. These residuals are recorded in the
    threat model (TB1, beside TM-TB1-T8) by T-1137. security-architect confirmed this in the re-review.

### 7. Performance budget

14. **p95 ≤ 200 ms per class, server-side**, measured by T-1102 as follows:
    - **Path:** in-process through the HTTP handler, including `rbac.ReadScopes.For`, the search
      statement and the metadata read.
    - **Dataset:** 50,000 objects in one tenant written through the real inventory writer: 30,000
      users, 8,000 groups, 10,000 computers and 2,000 contacts; two connections; OUs 6 levels deep;
      5 % duplicate display names; 10 % disabled.
    - **Runs:** 200 warm-up queries, then 1,000 queries per class: exact, prefix, one-typo fuzzy,
      no match, one letter, and a query whose class holds just under W matched key rows. The fuzzy
      runs record the posting rows read and the candidates rechecked, because that work is bounded
      by the tenant's postings and not by W (rule 13).
    - **Callers:** an unscoped caller (a whole naming context) and a scoped caller (one OU subtree
      with a large excluded sub-OU).
    - **Machine:** 4 vCPU, 8 GB RAM, local SSD, with PostgreSQL and the server on the same host.
    - **Versions:** PostgreSQL 16 and 18.

    The indicative split is `[PROPOSED]` ≤ 20 ms for the scope, ≤ 130 ms for the statement and
    ≤ 30 ms for metadata. The IA's "first results p95 ≤ 300 ms on the 100k-object tier" remains the
    scale-tier design target, beside T-0972, and does not gate M2a. Network and browser time are
    not in the budget. The console debounces input before it sends.

### 8. Search text handling and multi-tenant databases

15. **Search text never sits in a URL or a log line on the server.**
    - **API.** The API takes the query in a `POST` body (`directory.search`, T-1094). It is never
      in a path or a query string.
    - **Console.** The console's `/search?q=` route (IA §5.7) may keep `q` in the browser's address
      bar for back, forward and bookmarking. When that page is loaded straight from the server,
      the access log and the traces **redact `q` on every route**. The server records only the rune
      length, the recognised shape and the class set (T-1096).
    - **Handler.** The search handler, its errors and its traces never echo the text. A refused
      query (rule 7) is logged only with its refusal reason.
    - **Browser.** The console never navigates to a URL holding a query the browser has refused
      (IA §5.2).
16. **No tenant's fuzzy search reads, or is slowed by, another tenant's index entries.** Rev 3
    closes this rule by construction through rule 5a, and T-1332 proves it.
    - **The risk.** Revision 2's GIN index on `key` did not lead with `tenant_id`. In a shared
      database, one tenant's fuzzy scan would have read other tenants' posting lists, so its
      response time would have depended on their data. That is a timing side channel, not only a
      performance cost. The T-1314 spike measured it: for "johanson", 676 of the 1,234 rows rechecked
      belonged to the other tenant.
    - **What closes it.** Rule 5a's postings are a B-tree that leads with `tenant_id`, and the
      recheck is a lookup by `(tenant_id, key_id)`. Every stage of the statement therefore reads
      only the tenant's own index entries and rows.
    - **The proof.** T-1332 AC5 holds tenant B at the same 50,000-object key set as tenant A, and
      asserts that the `Actual Rows` of every scan node in A's fuzzy query are equal with B full
      and with B empty, on PostgreSQL 16 and 18. That test carries T-1136 AC2 and replaces its
      p95 comparison.
    - **No start-up gate is built** (T-1136 AC3 is dropped). ADR-0002 gives self-hosted profiles
      exactly one tenant row. No SaaS cell or MSP deployment exists, and none may serve fuzzy search
      before T-1332 lands. T-1136 is superseded by T-1332.

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
|---|---|---|
| **Keep live LDAP search** (`client.UserSearch` with ANR or contains filters), and add Go re-ranking | Always-current answers. No index to maintain. Works before inventory sync is complete | No typo tolerance: ANR and LDAP filters are prefix or substring only ([ANR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1a9177f4-0272-4ab8-aa22-3c3eafd39e4b)). A DC round trip per keystroke per connection, with no ranking across domains, cannot meet 200 ms. Trimming needs a second renderer (`Admits`) and live chain reads, and the hidden-entry scan is unbounded (T-0995). The IA rules it out (§5.2) |
| **An in-process search engine** (an in-memory trigram or FST index built from inventory, or a Go matcher from T-1092) | Very fast lookups, rich ranking, no extension prerequisite | A second copy of the inventory to keep consistent with the writer's transactions and with every replica. Memory grows per tenant (SaaS-ready, ADR-0002). It cannot trim in SQL, so it needs per-result `Admits`, a second renderer, or a cached ancestry that goes stale on a move. T-1092 found the Go matchers unusable as an engine (no index; subsequence or edit distance only) |
| **A separate search service** (OpenSearch, Meilisearch, Typesense) | Best-in-class fuzzy matching and relevance | Violates ADR-0001 rule 3 (one stateful service). Another thing for an on-prem customer to install, back up and secure. Several of these carry licences the register would have to clear for distribution. Scope trimming would need a renderer in that engine's query language |
| **`unaccent` in the database** instead of folding in Go | Folding happens next to the data, and ad-hoc SQL gets it too | Indexing requires an IMMUTABLE wrapper around a STABLE function. A rules-file change silently requires a REINDEX (T-1092). It is a second prerequisite extension. Query normalisation must match key normalisation exactly, and one Go function that both paths call, with unit vectors, guarantees that more cheaply |
| **PostgreSQL full-text search** (`tsvector`, `:*` prefix), with no extension at all | Built in. Word-prefix matching. No customer prerequisite | No typo tolerance at all, and stemming and stop-words are wrong for personal names and identifiers. We would still need `pg_trgm` for fuzzy matching, and then there would be two mechanisms |
| **Trim per result with `ReadScope.Admits`** after a tenant-wide candidate query | Reuses a decision function that already exists and is property-tested. Simple SQL | It is a second renderer, and it can disagree with the SQL one. A tenant-wide top-K fills with hidden rows, so a scoped technician sees fewer or no results, and the shortfall reveals hidden matches. To avoid that we would read until K rows are admitted, which is unbounded work (T-0995). It also carries inventory ancestry out of the store for Go to decide on |
| **A silent per-class candidate cap before the scope join** (revision 1 of this ADR: the top 5,000 keys per class, then trim) | Bounded results and a simple statement | Rejected in review. A GIN trigram index cannot do an ordered `LIMIT`, so the cap bounded the rows returned, not the rows examined. Worse, hidden objects could push a technician's own visible object out of the top 5,000. A broad query could then return fewer hits than a narrow one, which is a probe for hidden data (the T-0995 leak in a new form), and the counts were partial numbers shown as complete |
| **GiST `gist_trgm_ops` with `<<->` KNN**, reading fuzzy candidates in similarity order | Fuzzy rows read in index order, so an ordered `LIMIT` is cheap ([pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)) | Under rule 12 a ceiling hit withholds the class whole, so the order of reading never changes an answer, and the ordering buys nothing. GiST builds and set lookups are generally slower than GIN `[UNVERIFIED for trigram at 50k objects]`. Rev 3: its operators are not leakproof either, so under `FORCE` RLS it is unusable (§3a, option e) and is no longer a revisit option |
| **Scope as bound arrays in a static sqlc query** (terms passed as `uuid[]`/`smallint[]` and evaluated by a SQL function) | Fully static SQL. Plannable once | A second renderer, written in SQL, of the fail-closed rules RP6 proves for `scopeSQL`. It would need its own RP6, and the two would drift. Worth revisiting only if reports move to the same form, which would then be a superseding ADR for both |
| **A materialised visible set per account** (account × object table) | Trimming becomes a join, which is very fast | It must be recomputed on every assignment, group-membership, token or OU-move change. Its size is accounts × objects. A stale row is a disclosure. It duplicates `rbac.ReadScopes.For` |
| **Defer fuzzy matching** and ship exact and prefix over the inventory only | No extension prerequisite in M2a | The M2a promise (§8.2) is fuzzy matching. `pg_trgm` is trusted and present on every supported PostgreSQL, so deferring buys almost nothing |

## Consequences

**Positive**
- Search and reports trim by literally the same code (`scopeSQL`), under the same proof (RP6, which
  SE3 extends to the search template). There is no second renderer anywhere once T-1127 lands.
- One indexed statement per request gives a cost that is independent of the scope's shape. Exact
  and prefix are bounded by W, and fuzzy by the tenant's own trigram postings (rule 13).
- **Every stage reads only the tenant's own index entries** (rule 5a, rev 3). The fuzzy probe runs
  under the same RLS policy as everything else, with no definer function and no bypass, and rule 16
  is closed in every deployment profile. The answers are exact
  below the ceiling and the same for every caller above it. The 200 ms budget is a database index lookup, not a DC round trip.
- Fuzzy matching, prefix matching and ranking across domains come from one engine that needs no new
  Go dependency and no new stateful service. Its licence is the PostgreSQL Licence.
- The IA states work as designed: "Domain unreachable" is served from the last sync with `as of`,
  and "index as of" in the footer is the inventory freshness.
- The live-LDAP client, `SearchRoots`, `Admits` and T-0995's defect all disappear.

**Negative**
- **Customer prerequisite.** A customer-supplied PostgreSQL must have contrib installed, and on a
  managed service `pg_trgm` must be allow-listed `[UNVERIFIED]`. The installation guide and the
  preflight (T-1128) must say so.
- **Search is as fresh as the sync.** An object created a minute ago is not found until the next
  change-feed pass. This depends on the sync passes and watermark (T-0949, currently blocked, and
  T-1026). Until they land, search shows its `as_of` honestly and finds only what the inventory
  holds.
- **Many 2a identifier shapes are unserved** (rule 9) because the 2a sync set lacks the attributes.
  T-1129 extends it. T-1097's disambiguator cannot use title, office or department until then.
- **Entra objects are not findable at 2a** even though they are indexed, because no 2a scope kind
  admits them (T-1131).
- **Broad queries in large tenants get "keep typing".** When a class matches more than W key rows,
  every caller gets the refine state for it (rule 12). In a 50,000-object tenant that is typical
  for one-letter prefix queries. This is the price of a bound that reveals nothing about the scope.
  Exact identifier hits still show.
- **Fuzzy work is not bounded by W.** It is bounded by the tenant's postings for the query's
  trigrams and the 2 s timeout (rule 13). T-1332 and T-1102 measure it at 50k objects, and the scale
  tier must re-measure it.
- **We own a small piece of fuzzy-matching machinery** (rev 3): the posting table, its trigger and
  the candidate bound. Trigram extraction and the final `<%` test stay `pg_trgm`'s own. The
  candidate bound must remain a superset of `<%` across `pg_trgm` upgrades, and T-1332 AC3's oracle
  test guards that on every supported version.
- **Fuzzy matching covers `name` and `sam` only** (rev 3). A misspelt UPN or mail address finds its
  object only through the object's name or sAMAccountName.
- **Postings are about 15× the size of the GIN index they replace, and every key write fans out.**
  The spike measured 2.0 M rows and 277 MB per 50k objects, against a 39 MB GIN for two such
  tenants. Each `name` or `sam` key write also writes about 10–15 posting rows in the same
  transaction, which adds time to the first sync.
- **A residual is accepted.** The refine state and the response time reveal "the tenant holds many
  keys matching this text", the same to every caller. Timing can also, with many rate-limited samples,
  confirm that a named object exists (rule 13). T-1137 records both in the threat model.
- **Index volume.** Roughly 4–8 key rows per object, so about 0.3–0.4 M rows at 50k objects, plus
  the trigram postings (above). The sizing guide must count both. T-1332 AC6 records the measured
  size.
- **No frozen pages.** "Show all" pages can shift while the inventory changes.
- `reportsql` grows a non-report entry point. Its owner and its security review (P5 rule 3) now
  cover search too.

**Follow-on work** (filed from T-1093)
- **T-1126** `fitness-search` SE1–SE6 (devops-engineer). This ADR's fitness function.
- **T-1127** retire `searchDirectoryUsers`, `client.UserSearch`, `SearchRoots` and `Admits`; repoint
  `/directory/users` (backend-engineer; after T-1096 and T-1100).
- **T-1128** server preflight: refuse to migrate without `pg_trgm`, naming the package.
- **T-1129** sync-set extension for the search identifiers in rule 9 (directory-engineer).
- **T-1130** per-account recent objects for ranking and for the empty palette (P3).
- **T-1131** an Entra ID read-scope root kind for search and reports (spec).
- **T-1136** a tenant-isolated trigram index, and the rule-16 gate until it lands
  (directory-engineer). **Superseded by T-1332** (rev 3).
- **T-1332** (rev 3, from T-1314) the tenant-led trigram posting table, its trigger, the new
  `m_fuzzy` stage, dropping the GIN index, the flipped plan test, the two-tenant test, and the SE1,
  SE2 and SE5 changes, all in one change (directory-engineer; security-sensitive). T-1102 depends on
  it.
- **T-1137** the threat-model residuals of rules 13 and 16 (security-architect).
- **T-1138** move `localaccount.go`'s `authz_roles` query into `rbac`, which removes SE1's pending
  exception (backend-engineer).
- Build tickets already waiting on this ADR, with the constraints above added as notes:
  - T-1094: rule 12 (counts, the refine state, the opaque MAC-bound cursor, no counts under 3
    runes), timeout and 503; rule 15 (the query in a `POST` body);
  - T-1095: index shape and normalisation, rules 4–9 (rule 7's order and vectors, `PrefixUpper`
    edges, the ctype); the statement of rules 12–13 with W; the port takes the scopes (amends AC3);
  - T-1096: no `Admits`, the port only; the refusal order of rule 7; rule 15's log and trace
    redaction;
  - T-1097: disambiguator inputs come from T-1129;
  - T-1102: the budget in rule 14;
  - T-0988: rewrite the `dn` keys.

**Revisit when**
- **T-1102 or the scale tier misses the p95**, or the refine state shows up at realistic query
  lengths (three or more runes) in QA or in the field. Then consider:
  - a scope-driven variant inside `CompileSearch`, which starts from `ancestry @>` and joins the
    keys, still through `scopeSQL` and still applying the scope before every limit;
  - for fuzzy, the levers within rule 5a (§3a): rarest lists only, a per-tenant vocabulary, or
    `work_mem`.
- **PostgreSQL marks `pg_trgm`'s operators leakproof,** or adds a leakproof similarity operator.
  The GIN index would then work under RLS. It is still not tenant-led, so that alone would not meet
  rule 16.
- **Before any SaaS cell or MSP deployment serves fuzzy search,** T-1332 must have landed with AC5
  green (rule 16).
- **Customers need more typo tolerance on identifiers than trigrams give, or cross-script
  matching.** Then consider a `fuzzystrmatch` re-ranker over the rows below the ceiling.
- Any of these calls for a superseding ADR if it changes a rule above.

## Fitness function

Job **`fitness-search`** (`tools/fitness/search`, built by T-1126, in `make ci`). As in
`fitness-reports`, a check whose subject has not landed prints `pending`, which is not a pass. This
ADR is `accepted` only when SE1–SE5 are green in `make ci` with none pending and SE6 has passed once
in the nightly job. Each static check has a failing self-test fixture (T-1126).

- **SE1, one renderer and one reader of the scope's sources (typed with go/types, plus SQL).**
  - **Scope internals.** In non-test code, `authz.ReadScope.Terms` and `.Token` are called **only**
    in `internal/platform/store/reportsql`. Method values, method expressions and embedding count,
    as RP2 already checks.
  - **Who may use `Connections()`.** Outside `authz` and `reportsql`, `ReadScope.Connections()` is
    allowed only in `internal/modules/reports/run` and `internal/modules/search`, where it labels
    freshness.
  - **`Admits` and `SearchRoots`** are called nowhere outside `authz`. Until T-1127 deletes them,
    `internal/directory/client/usersearch.go` is the one listed exception, reported as `pending`.
  - **`reportsql.CompileSearch`** is called only from `internal/directory/inventory`.
  - **Go code that names the RBAC tables.** These tables are `authz_assignments`,
    `authz_assignment_roots`, `authz_roles` and `authz_role_permissions`, plus any later
    `authz_*` table that the owners map assigns to `rbac`. No non-test Go SQL text names them
    outside `internal/platform/rbac` and `internal/platform/authz`. The generated
    ownership map is `internal/platform/store/owners/owners.gen.tsv`, data rather than Go source (T-1155),
    so no exemption is needed. `internal/compose/server/localaccount.go` is the one listed exception, reported as
    `pending` until T-1138 moves its `authz_roles` count into `rbac`.
  - **Migrations that name the RBAC tables.** A migration may create, alter and index those tables,
    and may put policies and grants on them. It may define **no view, materialised view, rule, or
    non-trigger function or procedure whose body names them**. Trigger functions are allowed only
    when they are attached to an RBAC table and listed by name. Today's list is
    `authz_tier2_guard` (0018) and `authz_tenant_owner_role_guard` (0034, replaced by 0043). Without
    this rule, a migration could define a view that lets constant SQL elsewhere re-derive a scope.
  - **Who reads the key table and the postings.** Only the `reportsql` search template may read
    `inventory_search_keys` or `inventory_search_trigrams`, in a `FROM`, a `JOIN` or a subquery.
    - `internal/directory/inventory` may `INSERT`, `UPDATE` and `DELETE` the key table. Its one
      allowed read is the named backfill query, which projects only `(connection_id, object_guid,
      norm_version)` and never `key`.
    - No Go code writes `inventory_search_trigrams`.
    - No migration may define a view or function over either table. The one listed exception is the
      trigger function `inventory_search_trigrams_sync` (rule 5a). It must be `SECURITY INVOKER` and
      attached to `inventory_search_keys`, and it may read only that trigger's transition tables and
      write only `inventory_search_trigrams` (rev 3).
  - **When T-1127 lands,** RP2's allow-list in `fitness-reports` is narrowed to match.
- **SE2, no string-built search SQL and no stray trigram use (static, repo-wide).**
  - **Patterns.** The search template in `reportsql`, and every SQL constant or sqlc query file under
    `internal/directory/inventory` and `internal/modules/search`, contain no `LIKE`, `ILIKE`,
    `SIMILAR TO`, `~`, `~*`, `!~` or `!~*`.
  - **Trigram operators and functions.** These appear in SQL text **only in the `reportsql` search
    template**, anywhere in the repository, migrations included:
    - the operators `%`, `<%`, `%>`, `<<%`, `%>>`, `<->`, `<<->`, `<->>`, `<<<->` and `<->>>`;
    - the functions `similarity(`, `word_similarity(`, `strict_word_similarity(`, `show_trgm(`,
      `set_limit(` and `show_limit(`.

    The one exception is `show_trgm(` in the body of `inventory_search_trigrams_sync` (rule 5a,
    rev 3), as well as in the template. T-1095's `gin_trgm_ops` exception covers only the historical
    migration 0069, whose index T-1332 drops. No later migration may use a trigram operator class.
    Modulo arithmetic in SQL is written `mod(a, b)`, so a bare `%` is never ambiguous.
  - **Settings.**
    - No `SET` or `SET SESSION` of any `pg_trgm.*` setting.
    - `set_config(` appears only with a literal `true` as its third argument (transaction-local),
      repo-wide.
    - `set_config('pg_trgm.…', $n, true)` appears only in the search transaction, with a bound value.
  - **No hand-built SQL.** `modules/search` and the inventory search code build no SQL text at all.
    `sqlconst` (FF-SP2/RP1) already forbids non-constant SQL there, and SE2 asserts that the
    analyser covers those packages.
  - **Bound `LIKE` patterns.** Repo-wide, a `LIKE`/`ILIKE` with a bound pattern must take a
    `store.LikePattern` argument (P5 rule 4).
- **SE3, search scope equals the oracle, and nothing leaks from the unscoped stages (integration,
  PostgreSQL 16 and 18).** `Test_search_scope_matches_read_oracle` reuses RP6's world generator:
  trees written through the writer, OU moves, incomplete ancestry, two connections, flawed terms and
  token layers. It adds random queries in every class, and worlds whose matching key volume falls
  below, at and above W.
  - **Below the ceiling.** The hits are exactly the objects that match the query and that
    `AuthorizeRead` admits. The group counts and the `more` flags are the oracle's.
  - **Above the ceiling.** `refine` is true, there are no counts, and the classes ranked above the
    ceiling class are still exact.
  - **`refine` is the same for every caller in a world who holds the same permissions.** The test
    compares an unscoped caller and a scoped caller.
  - **Invariance (M4).** Add or remove hidden matching objects without crossing W, and every scoped
    response is identical: hits, order, counts, `more` and cursor.
  - **Gated kinds.** A world with BitLocker key-ID keys and a caller without the BitLocker
    permission gives exactly that caller's response in the same world with no such keys.
  - **Cursors.** A cursor replayed with another query, another facet or another scope fingerprint is
    400.
  - **Empty scopes.** A scope that renders `FALSE` gives zero hits and its reason.
  - **The template itself.** A `reportsql` unit test asserts that the outer `SELECT`, `ORDER BY`,
    window and `LIMIT` clauses reference only `hits` and `ceiling_hit`.
- **SE4, hostile, normalisation and secrecy vectors (integration).**
  - **Hostile text.** `%`, `_`, `\`, quotes, `$1`, `'; --` and `E'\x00'`-style text match literally
    or not at all.
  - **Refusals.** NUL, invalid UTF-8, more than 4 KiB of raw bytes and 257 NFKC runes are refused
    (400).
  - **Recovery passwords.** A 48-digit recovery password, in ASCII, in full-width digits and in
    another script's digits, with and without dashes, is refused. It does not appear in the logs, in
    the traces or in the access log.
  - **Search text.** `q` on the console's `/search` route appears in no access-log or trace line;
    only its length does (rule 15).
  - **Folding.** Every row of rule 7's vector table folds the same way for keys and for queries.
    That includes the upper-case and lower-case pairs Ł/ł, Ø/ø and İ/i, and `ẞ`.
  - **`PrefixUpper`.** The U+D7FF and U+10FFFF edges give the bounds rule 8 states.
  - **Secret attributes.** Seed every one of these: `ms-Mcs-AdmPwd`, `msLAPS-Password`,
    `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`, `msDS-ManagedPassword`,
    `msFVE-RecoveryPassword`, and a custom attribute marked confidential in `searchFlags` (0x80).
    No value of any of them appears in `inventory_search_keys`.
- **SE5, bounded work (integration).** `Test_search_work_is_bounded` (renamed from `…_and_silent`, because the cap is no longer silent):
  - **Setup:** a scoped technician with 5 visible matches, and an excluded OU holding H matching
    objects, for H in {0, W − 10, W + 10, 20,000}.
  - **Plan shape.** The check runs `EXPLAIN (ANALYZE, FORMAT JSON)` of the compiled statement under
    `FORCE` RLS as the runtime role, on PostgreSQL 16 and 18 (rev 3). The plan must:
    - use the key B-tree for exact and prefix;
    - for fuzzy, use `inventory_search_trigrams_pkey` with `tenant_id` and `trgm` in its
      `Index Cond`, then the `(tenant_id, key_id)` index for the recheck;
    - have no `Seq Scan` on `inventory_search_keys`, `inventory_search_trigrams` or
      `directory_objects`.

    `Test_search_plan_uses_the_indexes` asserts the same shape and no longer pins the limit.
  - **Rows examined.** The check asserts on **the scan nodes' actual rows**, never on the `Limit`
    node:
    - exact and prefix: the B-tree `Index Scan` or `Index Only Scan` nodes of each class have
      `Actual Rows` summing to W + 1 or fewer;
    - fuzzy: the recheck stage returns W + 1 rows or fewer. The posting rows read and the
      candidates rechecked are recorded and reported for SE6, but are not bounded by W (rule 13);
    - the join to `directory_objects` has 3(W + 1) or fewer loops.
  - **Answers.** With H = W − 10, the technician's response equals the H = 0 response exactly. With
    H = W + 10 and 20,000, the response is the refine state, and it equals an unscoped admin's
    refine state for the same query.
- **SE6, latency (nightly, behind the large-dataset switch).** T-1102's benchmark to rule 14's
  budget: per class, scoped and unscoped, including the ceiling-sized class, on PostgreSQL 16 and 18.
  A miss fails the nightly job and names the class and the percentile.

`fitness-tenancy` (ADR-0002) covers RLS, `FORCE` and the tenant-led primary keys of
`inventory_search_keys` and `inventory_search_trigrams`. `fitness-stack` F4 covers the absence of
new Go dependencies. Rule 16 is proved by T-1332 AC5's two-tenant scan-rows test, which joins SE5's
bindings when it lands.
