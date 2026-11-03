---
title: fitness-search — enforcing ADR-0011 (SE1–SE6)
date: 2026-11-02
updated: 2026-11-02
ticket: T-1126
status: draft
owner: devops-engineer
---

# fitness-search: how the job works and how a build ticket plugs into it

Enforces the "Fitness function" section of
[ADR-0011](../decisions/0011-universal-search-over-inventory-pg-trgm-one-scope-renderer.md) (the ticket's
older acceptance text is stale; the ADR section and the director's note of 2026-10-31T12:20 rule).
`make fitness-search` is part of `make fitness`, so of `make ci`; `make fitness-search-nightly` is part of
`make fitness-nightly`. The bound tests need Docker (PostgreSQL 16 and 18 containers); with `CI` set a
missing Docker fails the job instead of skipping it. Tool: `tools/fitness/search`. No new dependency
(it uses `golang.org/x/tools/go/packages`, already in `go.mod`), so no licence-register entry.

| Check | What fails |
| --- | --- |
| SE1 | `ReadScope.Terms`/`.Token` outside `store/reportsql`; `Admits`/`SearchRoots` outside `authz`; `Connections` outside `authz`, `reportsql`, `reports`, `reports/run`, `modules/search`; `CompileSearch` outside `internal/directory/inventory`; embedding `ReadScope` or re-declaring its methods in an interface (type-checked); an RBAC assignment table named in SQL outside `rbac`, `authz`, migrations (Go constants, `.sql` files, and any new `authz_*` table in `owners.gen.tsv`); a migration view, matview, rule or non-trigger function over those tables (the guards `authz_tier2_guard`, `authz_tenant_owner_role_guard`, `authz_control_plane_guard` are allowed and must be attached by `CREATE TRIGGER`); `inventory_search_keys` read by anything but the template, the key writers and the named backfill projection; `inventory_search_trigrams` named in SQL outside the template (Go code never writes it: the triggers do); a migration view or function over either table except `inventory_search_trigrams_sync`, which must be `RETURNS trigger`, `SECURITY INVOKER`, `SET search_path = pg_catalog, public`, call `public.show_trgm`, read only its triggers' transition tables, write only the postings, and be attached to `inventory_search_keys` by exactly one AFTER INSERT, one AFTER DELETE and one AFTER UPDATE (no column list) statement trigger; any index or unique/primary-key/exclusion constraint on either table whose first column is not `tenant_id` (unless a later migration drops it) |
| SE2 | `LIKE`, `ILIKE`, `SIMILAR TO`, POSIX operators (`~ ~* !~ !~*`) or regex functions in the search packages and the template; a trigram operator (`% <% %> <<% %>> <-> <<-> <->> <<<-> <->>>`) or function (`similarity`, `word_similarity`, `strict_word_similarity`, `show_trgm`, `set_limit`, `show_limit`) outside the template, migrations included (`show_trgm` is also allowed in the body of `inventory_search_trigrams_sync` and in the `INSERT INTO inventory_search_trigrams` that backfills the postings; no trigram operator class survives: `gin_trgm_ops` in migration 0069 is accepted only because 0072 drops that index); `SET pg_trgm.*`; a `set_config` whose third argument is not literal `true`, or on `pg_trgm.*` outside `store/localsetting.go` and not bound; a `LIKE` operand that is not a `store.LikePattern`; the search packages missing from `sqlconst` coverage |
| SE3 | `Test_search_template_never_outputs_key_id` (`key_id` appears only inside `m_fuzzy`, in no output column, hit or cursor); `Test_search_scope_matches_read_oracle` (subtests `pg16`/`pg18`, inner `oracle`, `invariance_M4`, `above_ceiling`, `gated_kinds`, `empty_scope`) and the other bound tests of that check |
| SE4 | hostile-input and folding vectors, the search text as a bound parameter, no secret attribute stored, the logging tests |
| SE5 | `Test_search_work_is_bounded` on `pg16` and `pg18` (rows examined on the scan nodes, `Rows Removed by Filter` = 0, no Seq Scan; subtests `fuzzy_plan` and `fuzzy_longest`: the fuzzy class reads `inventory_search_trigrams_pkey` by Index Only, Index or Bitmap Index Scan with `tenant_id` and `trgm` in the Index Cond, rechecks through a correlated Index Scan of `(tenant_id, key_id)`, never a Hash or Merge Join onto the keys, and a 32-rune query keeps that shape) |
| SE6 | `TestSearchLatency50k`, **nightly only**, `pg16` and `pg18`, 50,000 objects |

SQL text is tokenised before SE2 judges it: string literals, comments and dollar-quoted bodies are skipped, so
the `RAISE EXCEPTION '… %'` placeholders and `LIKE '%…%'` literals in old migrations do not trip the `%`
rule. `%ROWTYPE`/`%TYPE` are ignored. In `tools/` (not `internal/`, `cmd/`) a string with a printf verb is a
format string and its `%` is ignored; product code is strict. A Go string counts as SQL only if it starts
with a statement keyword and holds a clause keyword.

## Pending is not a pass

A part whose code has not landed prints `pending` on every run and the job still exits 0. A static check or a
bound test that ran and found nothing prints `pass`; a check with a pending part or a violation is never listed
as `pass` for the static lines, while each landed bound test is listed by itself. ADR-0011 stays `ratified`
until SE1–SE5 print `pass` with nothing pending and SE6 has passed once in the nightly.

## Listed exceptions (tools/fitness/search/static.go `defaultExceptions`)

Each is tied to a file and a rule. A pending one prints as pending. An exception that stops matching is a
violation (`stale-exception`): whoever removes the cause deletes the entry in the same change.

| File | Rule | Who deletes it |
| --- | --- | --- |
| `internal/directory/client/usersearch.go` | SE1 `scope-members` (Admits/SearchRoots) | T-1127 (retires the live-LDAP user search) |
| `internal/compose/server/localaccount.go` | SE1 `rbac-table-sql` (counts `authz_roles`) | T-1138 (moves the count into `rbac`) |
| `internal/directory/inventory/closure.go` | SE2 `pattern-operator` (`~` regex on the privileged SID) | T-1322 |
| `tools/fitness/tenancy/probes.go` | SE2 `set-config-persistent` (SQL-14 probe passes `$2` on purpose) | permanent, printed as a note |

## Landing a bound test

In `tools/fitness/search/bindings.go` set `Landed: true` (and `Pkg` if elsewhere). Do it in the same change as
the test: a test that is declared while its binding is not `Landed` fails the job (`binding-not-landed`), and
a landed one that is renamed, missing, failed, skipped, or lacks a `pg16`/`pg18` subtest fails. Pending rows
today: T-1096's three tests (`./internal/modules/search`), T-1323's two (reportsql template, console route
log), SE6 from T-1102. When T-1096 merges after this ticket (or the reverse), the first to land flips the
bindings; a `binding-not-landed` failure on main means that was missed.

## Large-dataset switch (SE6)

`go run ./tools/fitness/search -nightly` (`make fitness-search-nightly`) runs only the `Nightly` bindings with
`ACTIVEDIQ_SEARCH_LARGE_OBJECTS=50000`. The per-change run never sets it, so no PR pays for 50k rows. The job
unsets `ACTIVEDIQ_TEST_PG_VERSIONS` so both PostgreSQL versions always run.

## Reading a failure

`path:line SEn [rule]: message`. Fix the code, not the check. To see what each rule catches, read the failing
fixture in `tools/fitness/search/check_test.go` (`go test ./tools/fitness/search -run TestSE2… -v`; the suite
takes about a minute, each fixture type-checks a small module). The CLI is also proved by
`tools/ci/proof.sh` (`make ci-proof`): a clean tree, SE1 ×2, SE2 ×3 and a stale exception.

## Known limits

- Typed rules load the host platform's build (non-test files); build-tagged code for another OS is not judged.
- SE1 judges references, not data flow; reflection is banned by review.
- The 2a key kinds are all `directory.read`, so the `gated_kinds` subtest of SE3 has nothing gated to test; it
  fails the day a gated kind appears until the two-BitLocker-holder world exists (T-1323).
- Rule 16's start-up gate (two tenants → no fuzzy matching, shown on the health page) is covered by T-1136 AC3.
