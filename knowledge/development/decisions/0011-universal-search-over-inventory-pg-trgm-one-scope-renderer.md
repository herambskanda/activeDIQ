---
title: "ADR-0011: Universal search runs over the inventory with pg_trgm, and is trimmed in the same SQL statement by the one ReadScope renderer in store/reportsql"
date: 2026-10-31
updated: 2026-10-31
status: proposed
owner: heramb
author: solution-architect
kind: technical
ticket: T-1093
fitness: fitness-search SE1–SE5 (in make ci) and SE6 (nightly); T-1126 builds it. Not yet in CI, so not `accepted`
---

# ADR-0011: Universal search runs over the inventory with pg_trgm, and is trimmed in the same SQL statement by the one ReadScope renderer in `store/reportsql`

**Status:** proposed. factory-director ratifies after review. Because the ticket is tagged
security-sensitive, security-architect reviews it too, in particular rule 5 (the work bound and
what an answer may reveal). `accepted` when `fitness-search` SE1–SE5 run green in `make ci` and SE6
has passed once in the nightly job.
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

   The bundled PostgreSQL 18 image must ship contrib. A customer-supplied server must have the
   contrib package installed (for example the distribution's `postgresql-16-contrib` or equivalent
   `[UNVERIFIED per distribution]`) and must allow `pg_trgm` on managed services
   (`[UNVERIFIED]`). The server's preflight checks `pg_available_extensions` before it migrates and
   refuses to migrate with a message that names the missing package (T-1128). It never fails
   halfway through a migration.

### 3. Index shape (owned by `inventory`, built by T-1095)

5. A table `inventory_search_keys` holds the search keys, and `internal/directory/inventory` is its
   only SQL owner (ADR-0003 rule 6).
   - **Columns and key.** `(tenant_id, connection_id, object_guid, key_kind smallint, key text
     COLLATE "C", norm_version smallint)`. The primary key is all of these except `norm_version`.
     A foreign key points to `directory_objects (tenant_id, connection_id, object_guid)`. The table
     has RLS with `FORCE` and the one fail-closed policy shape.
   - **Indexes.** A B-tree on `(tenant_id, key_kind, key)` serves exact and prefix matches. A GIN
     index `gin_trgm_ops` on `key`, partial to the fuzzy-eligible kinds (rule 9), serves fuzzy
     matches.
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

### 4. Normalisation (one function, used for keys and for queries)

7. A leaf package `internal/platform/searchkey` holds the normalisation. It imports only the
   standard library and `golang.org/x/text`, which is already in the register. It is the **only**
   code that normalises search text. The writer uses it to build keys and `modules/search` uses it
   to classify and normalise the query, so the two can never drift apart.
   - **Refusals.** Invalid UTF-8, NUL and a query over 256 runes are refused (400) before anything
     else happens (P5 rule 7).
   - **Name keys and name queries** (`NormName`) go through these steps in order:
     1. NFKC, so full-width letters and ligatures fold to their plain forms.
     2. NFD, then removal of combining marks (`unicode.Mn`).
     3. An explicit table for letters that do not decompose: ł→l, đ→d, ø→o, ħ→h, ı→i, ŀ→l, ß→ss,
        æ→ae, œ→oe, þ→th. This covers the Łódź→lodz case that T-1092 showed `pg_trgm` alone cannot
        fold.
     4. Full Unicode case folding (`cases.Fold`).
     5. Punctuation `, . - ' _ ( )` becomes a space, runs of whitespace collapse to one space, and
        the result is trimmed.
   - **Identifier keys and queries** (`NormIdent`) are NFKC, case-folded and trimmed. Their
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
   | `fuzzy` | Only when the normalised query has at least 3 runes: `$q <% key` (`pg_trgm` word similarity) over fuzzy-eligible kinds. The threshold is set per transaction through the static statement `SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)`. It is `[PROPOSED]` 0.5 and T-1095/T-1102 tune it against the 'Pryia Ramn' vector | GIN `gin_trgm_ops` |

   **No search SQL uses `LIKE`, `ILIKE`, `SIMILAR TO` or a POSIX regex.** Prefix is the bound range
   above, so no user text ever becomes a pattern. Within a class, results order like this:
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
   | Free text | `display_name`; `rdn` (cn) | `name`, `name_word` (prefix, fuzzy) | `givenName` + `sn` in both orders, `title`, `department` → **T-1129** (until then "Raman, Priya" matches a displayName or cn written in either order, through the comma swap and trigram order-insensitivity) |
   | `sam`, `DOMAIN\sam`, `sam@dnsdomain` | `sam_account_name`; computers also without the trailing `$` | `sam` (exact, prefix, fuzzy) | The `DOMAIN\` and `@dnsdomain` parts narrow to the connection whose NetBIOS or DNS domain name matches, **if** the connection record holds that name (T-1095 confirms). Otherwise the domain part is dropped and `sam` matches in every connection. It is never an error |
   | `x@y` | `upn`; contact `mail` (D3) | `upn`, `mail` (exact, prefix, fuzzy) | user `mail`, `proxyAddresses`, `mailNickname` → **T-1129** |
   | Digits | none | | `employeeID`, `employeeNumber` → **T-1129**. Until then digits are matched as free text |
   | `S-1-5-…` | `sid` (canonical string form) | `sid` (exact) | `sIDHistory` → **T-1129** |
   | GUID, with or without braces | `object_guid`; `consistency_guid` (as a GUID and as base64) | `guid`, `consistency_guid` (exact) | The Entra object ID is indexed, but Entra objects are **admitted by no 2a scope kind**: they carry no `nc_guid`, and the 2a kinds are AD-only. They become findable when an Entra read-scope root kind exists → **T-1131** |
   | `CN=…,DC=…` | `dn` snapshot | `dn` (exact) | Descendants of a moved OU have stale `dn` keys until T-0988 lands. Rule 5 requires T-0988 to rewrite their keys too |
   | Host name or FQDN | computer `rdn`/`sam` without `$`; `dNSHostName` | `name`, `dns_host` (exact, prefix) | `servicePrincipalName` values → **T-1129** |
   | 8 hex characters (BitLocker key ID) | none | | `msFVE-RecoveryInformation` child CN only, **never** the recovery password; Entra-escrowed keys come from Graph → **T-1129** |
   | 48-digit recovery password | **refused**: 400, never echoed or logged (T-1096 AC5), as well as refused in the browser (IA §5.2) | | |

   The shape is recognised in `searchkey.Classify` and is never passed through to SQL as a string
   to interpret. A recognised shape adds the `exact` branch. Name matching (`prefix`, `fuzzy`)
   still runs, so `jsmith` also prefix-matches "jsmith2".

### 6. Trimming: one producer, one renderer, in the statement

10. **Producer.** The caller's scope is `rbac.ReadScopes.For(…, directory.read)`, reached through
    the composed port (T-0987). It is the only producer: RP2 already confines `NewReadScope` to
    `rbac` and `authz`. Every error and every empty scope answers nothing: `ErrOwnerDead`,
    `ErrTokenRefused`, `ErrUnsupportedChain`, no producer (403), `Empty`.
11. **Renderer: search reuses the reports renderer through one new exported entry point, and uses
    no per-result `Admits`.** `store/reportsql` gains
    `CompileSearch(src SearchSource, q SearchQuery, scope authz.ReadScope) (Query, error)`.
    - `SearchSource` is registered by `inventory`, as datasets are. It names the key table and the
      `directory_objects` anchor columns, pre-quoted once at registration.
    - `SearchQuery` is a typed value: normalised text, class set, kinds, type facet, per-group
      limit, cursor, candidate cap. It holds no SQL fragments.
    - `CompileSearch` returns the existing `reportsql.Query`, so RP1 and `sqlconst` apply unchanged.
    - The statement is a fixed template inside `reportsql`. Its scope position is filled by the
      existing `planScope` and `scopeSQL` over the `directory_objects` anchor, the same functions
      RP6 proves. So `ancestry_complete`, the fail-closed rules, the 512-term cap
      (`ErrScopeTooLarge`) and `ScopeReasons` all carry over unchanged.
    - Only `internal/directory/inventory` calls `CompileSearch` (SE1). `modules/search` reaches it
      through the port `inventory.Search(ctx, tx, tenant, scope authz.ReadScope, q)`, composed in
      `compose/server`. The port **takes the scope and returns trimmed hits**. It never returns
      ancestry for the caller to trim with: this amends T-1095 AC3.
12. **Counts, limits and pages come after trimming (LF-39).** The statement has this shape (sketch;
    T-1095 fixes the text):

    ```
    cand  := per class: matching keys, ordered by class rank, LIMIT $cap        -- candidate cap (rule 13)
    best  := DISTINCT ON (connection_id, object_guid): each object's best class
    hits  := best JOIN directory_objects t USING (tenant_id, connection_id, object_guid)
             WHERE <scope(t) from scopeSQL>  AND  <type facet, bound>
    out   := row_number() OVER (PARTITION BY kind ORDER BY rank) <= $group_limit + 1,
             count(*) OVER (PARTITION BY kind)                       -- admitted rows only
    ```

    - Every count, every "more" flag and every cursor is computed over `hits`, which holds admitted
      rows only. No number in a response is ever computed from rows the scope rejects.
    - **A group's count is shown only when the normalised query has at least 3 runes.** For one-
      and two-rune queries a group shows its first results and "Show all" with no number.
    - `more` is true only when admitted hits exceed the group limit.
    - "Show all" (`/search`, IA §5.7) pages with a keyset cursor over the rank tuple of admitted
      hits, 50 per page, and stops at 1,000 admitted hits with "refine your search". That stop
      depends only on admitted rows.
    - Search is not a frozen report run (ADR-0010 does not apply). A page re-runs the statement, so
      pages may shift if the inventory changes in between.
13. **Work per query is bounded, whatever the scope's shape (T-0995 class).** These caps are
    `[PROPOSED]`; T-1102 measures them:
    - at most **one** search statement per request, plus at most one batched metadata read keyed
      by the admitted GUIDs (T-1097). There are no per-hit queries;
    - a candidate cap of **`MaxSearchCandidates` = 5,000 key rows per class** before the scope
      join, in rank order. This cap fixes the rows examined, independent of how many objects the
      scope hides;
    - per-group limit of at most 50, and scope terms of at most 512 (existing);
    - `fuzzy` only from 3 runes, so a one-letter query does exact and B-tree prefix only;
    - the store's per-transaction `statement_timeout` (SQL-22), set to 2 s for search, as a safety
      net. A timeout is a generic 503 "search unavailable" with a trace ID and no count;
    - the platform rate limiter answers 429 (T-1094 AC4).

    **What a cap hit may reveal: nothing new.** The cap is silent. It sets no flag, returns no
    error, and changes no count beyond leaving out admitted objects that rank below 5,000 better
    candidates. The only thing a technician could infer is that a very broad query matched many
    objects in the tenant, and that is true of any delegated domain. Security-architect confirms
    this outcome in review: it is the decision T-0995 asked to be taken with them. If it is
    refused, rule 13 is amended before ratification.

### 7. Performance budget

14. **p95 ≤ 200 ms per class, server-side**, measured by T-1102 as follows:
    - **Path:** in-process through the HTTP handler, including `rbac.ReadScopes.For`, the search
      statement and the metadata read.
    - **Dataset:** 50,000 objects in one tenant written through the real inventory writer: 30,000
      users, 8,000 groups, 10,000 computers and 2,000 contacts; two connections; OUs 6 levels deep;
      5 % duplicate display names; 10 % disabled.
    - **Runs:** 200 warm-up queries, then 1,000 queries per class (exact, prefix, one-typo fuzzy,
      no match, one letter).
    - **Callers:** an unscoped caller (a whole naming context) and a scoped caller (one OU subtree
      with a large excluded sub-OU).
    - **Machine:** 4 vCPU, 8 GB RAM, local SSD, with PostgreSQL and the server on the same host.
    - **Versions:** PostgreSQL 16 and 18.

    The indicative split is `[PROPOSED]` ≤ 20 ms for the scope, ≤ 130 ms for the statement and
    ≤ 30 ms for metadata. The IA's "first results p95 ≤ 300 ms on the 100k-object tier" remains the
    scale-tier design target, beside T-0972, and does not gate M2a. Network and browser time are
    not in the budget. The console debounces input before it sends.

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
|---|---|---|
| **Keep live LDAP search** (`client.UserSearch` with ANR or contains filters), and add Go re-ranking | Always-current answers. No index to maintain. Works before inventory sync is complete | No typo tolerance: ANR and LDAP filters are prefix or substring only ([ANR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1a9177f4-0272-4ab8-aa22-3c3eafd39e4b)). A DC round trip per keystroke per connection, with no ranking across domains, cannot meet 200 ms. Trimming needs a second renderer (`Admits`) and live chain reads, and the hidden-entry scan is unbounded (T-0995). The IA rules it out (§5.2) |
| **An in-process search engine** (an in-memory trigram or FST index built from inventory, or a Go matcher from T-1092) | Very fast lookups, rich ranking, no extension prerequisite | A second copy of the inventory to keep consistent with the writer's transactions and with every replica. Memory grows per tenant (SaaS-ready, ADR-0002). It cannot trim in SQL, so it needs per-result `Admits`, a second renderer, or a cached ancestry that goes stale on a move. T-1092 found the Go matchers unusable as an engine (no index; subsequence or edit distance only) |
| **A separate search service** (OpenSearch, Meilisearch, Typesense) | Best-in-class fuzzy matching and relevance | Violates ADR-0001 rule 3 (one stateful service). Another thing for an on-prem customer to install, back up and secure. Several of these carry licences the register would have to clear for distribution. Scope trimming would need a renderer in that engine's query language |
| **`unaccent` in the database** instead of folding in Go | Folding happens next to the data, and ad-hoc SQL gets it too | Indexing requires an IMMUTABLE wrapper around a STABLE function. A rules-file change silently requires a REINDEX (T-1092). It is a second prerequisite extension. Query normalisation must match key normalisation exactly, and one Go function that both paths call, with unit vectors, guarantees that more cheaply |
| **PostgreSQL full-text search** (`tsvector`, `:*` prefix), with no extension at all | Built in. Word-prefix matching. No customer prerequisite | No typo tolerance at all, and stemming and stop-words are wrong for personal names and identifiers. We would still need `pg_trgm` for fuzzy matching, and then there would be two mechanisms |
| **Trim per result with `ReadScope.Admits`** after a tenant-wide candidate query | Reuses a decision function that already exists and is property-tested. Simple SQL | It is a second renderer, and it can disagree with the SQL one. A tenant-wide top-K fills with hidden rows, so a scoped technician sees fewer or no results, and the shortfall reveals hidden matches. To avoid that we would read until K rows are admitted, which is unbounded work (T-0995). It also carries inventory ancestry out of the store for Go to decide on |
| **Scope as bound arrays in a static sqlc query** (terms passed as `uuid[]`/`smallint[]` and evaluated by a SQL function) | Fully static SQL. Plannable once | A second renderer, written in SQL, of the fail-closed rules RP6 proves for `scopeSQL`. It would need its own RP6, and the two would drift. Worth revisiting only if reports move to the same form, which would then be a superseding ADR for both |
| **A materialised visible set per account** (account × object table) | Trimming becomes a join, which is very fast | It must be recomputed on every assignment, group-membership, token or OU-move change. Its size is accounts × objects. A stale row is a disclosure. It duplicates `rbac.ReadScopes.For` |
| **Defer fuzzy matching** and ship exact and prefix over the inventory only | No extension prerequisite in M2a | The M2a promise (§8.2) is fuzzy matching. `pg_trgm` is trusted and present on every supported PostgreSQL, so deferring buys almost nothing |

## Consequences

**Positive**
- Search and reports trim by literally the same code (`scopeSQL`), under the same proof (RP6, which
  SE3 extends to the search template). There is no second renderer anywhere once T-1127 lands.
- One indexed statement per request, with fixed caps, gives a predictable cost that is independent
  of the scope's shape. The 200 ms budget is a database index lookup, not a DC round trip.
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
- **The candidate cap can hide low-ranked visible results** for very broad queries from a narrowly
  scoped technician. This is the price of bounded work (rule 13).
- **GIN on `key` is not tenant-led.** `gin_trgm_ops` cannot lead with `tenant_id` without
  `btree_gin`. In a multi-tenant (SaaS or MSP) database a fuzzy scan reads other tenants' index
  entries before RLS filters them. That is a performance problem, not a disclosure, because the
  heap rows are RLS-filtered and the response is trimmed.
- **Index volume.** Roughly 4–8 key rows per object, so about 0.3 M rows at 50k objects, plus the
  GIN index. The sizing guide must count it.
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
- Build tickets already waiting on this ADR, with the constraints above added as notes:
  - T-1094: counts rule 12, no counts under 3 runes, timeout and 503;
  - T-1095: index shape rules 4–7 and 9; the port takes the scope (amends AC3);
  - T-1096: no `Admits`, the port only;
  - T-1097: disambiguator inputs come from T-1129;
  - T-1102: the budget in rule 14;
  - T-0988: rewrite the `dn` keys.

**Revisit when**
- T-1102 or the scale tier misses the p95 for the scoped caller, or QA finds visible results lost to
  the candidate cap at realistic query lengths. Then add a scope-driven query variant inside
  `CompileSearch` (start from `ancestry @>` and join the keys), still through `scopeSQL`.
- A multi-tenant deployment shows cross-tenant GIN cost. Then consider `btree_gin` (after a
  register check) or per-tenant partial indexes.
- Customers need typo tolerance on identifiers beyond trigrams, or cross-script matching. Then
  consider a `fuzzystrmatch` re-ranker over the capped candidates.
- Any of these calls for a superseding ADR if it changes a rule above.

## Fitness function

Job **`fitness-search`** (`tools/fitness/search`, built by T-1126, in `make ci`). As in
`fitness-reports`, a check whose subject has not landed prints `pending`, which is not a pass. This
ADR is `accepted` only when SE1–SE5 are green in `make ci` with none pending and SE6 has passed once
in the nightly job.

- **SE1, one renderer (typed, go/types).**
  - In non-test code, `authz.ReadScope.Terms` and `.Token` (method values and method expressions
    included, embedding included, as RP2 already does) are called **only** in
    `internal/platform/store/reportsql`.
  - `ReadScope.Admits` and `.SearchRoots` are called nowhere outside `authz`. Until T-1127 deletes
    them, `internal/directory/client/usersearch.go` is the one listed exception, reported as
    `pending`.
  - `reportsql.CompileSearch` is called only from `internal/directory/inventory`.
  - No non-test SQL text outside `internal/platform/rbac`, `internal/platform/authz` and
    `migrations/` names the RBAC assignment tables. This closes the bypass of re-deriving a scope in
    SQL without a `ReadScope`.
  - RP2's allow-list in `fitness-reports` is narrowed to match when T-1127 lands.
- **SE2, no string-built search SQL (static).**
  - The search template in `reportsql` and every SQL constant or sqlc query file under
    `internal/directory/inventory` and `internal/modules/search` contain no `LIKE`, `ILIKE`,
    `SIMILAR TO`, `~`, `~*`, `!~` or `!~*`.
  - `set_config('pg_trgm.…', …)` appears only with a bound value.
  - `modules/search` and `inventory` search code build no SQL text at all. `sqlconst` (FF-SP2/RP1)
    already forbids non-constant SQL there, and SE2 asserts that the analyzer covers those packages.
  - Repo-wide, a `LIKE`/`ILIKE` with a bound pattern must take a `store.LikePattern` argument
    (P5 rule 4).
- **SE3, search scope equals the oracle (integration, PostgreSQL 16 and 18).**
  `Test_search_scope_matches_read_oracle` reuses RP6's world generator: trees written through the
  writer, OU moves, incomplete ancestry, two connections, flawed terms and token layers. It adds
  random queries in every class. Search hits must equal the objects that both match the query and
  are admitted by `AuthorizeRead`. Group counts must equal the oracle's counts. A scope that renders
  `FALSE` must give zero hits and its reason.
- **SE4, hostile and normalisation vectors (integration).**
  - `%`, `_`, `\`, quotes, `$1`, `'; --` and `E'\x00'`-style text match literally or not at all.
  - NUL, invalid UTF-8 and 257 runes are refused (400).
  - A 48-digit recovery password is refused and does not appear in the logs.
  - Diacritic and Ł/ø/ß folding is equal for keys and queries.
  - A seeded secret or confidential attribute never appears in `inventory_search_keys`.
- **SE5, bounded work, nothing revealed (integration).**
  `Test_search_work_is_bounded_and_silent`:
  - **Setup:** a scoped technician with 5 visible matches and an excluded OU holding 20,000
    matching objects.
  - **Bound:** `EXPLAIN (ANALYZE, FORMAT JSON)` shows that the candidate node reads at most
    `MaxSearchCandidates` rows per class.
  - **Silence:** the technician's response, compared with the same search after the hidden OU is
    emptied, differs in nothing except visible hits that rank below the cap. Its counts and `more`
    flags equal the counts over admitted hits.
- **SE6, latency (nightly, behind the large-dataset switch).** T-1102's benchmark to rule 14's
  budget: per class, scoped and unscoped, on PostgreSQL 16 and 18. A miss fails the nightly job and
  names the class and the percentile.

`fitness-tenancy` (ADR-0002) covers RLS, `FORCE` and the tenant-led primary key of
`inventory_search_keys`. `fitness-stack` F4 covers the absence of new Go dependencies.
