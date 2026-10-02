---
title: "fitness-tenancy: what it checks, the bootstrap contract and the exemption registry"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
ticket: T-0036
sources_last_checked: 2026-10-02
---

# fitness-tenancy

The job that enforces [ADR-0002](../decisions/0002-deployment-model.md) (tenancy from migration 1) and
safe-primitives FF-SP7 ([safe-primitives.md](safe-primitives.md) §8) in `make ci`. One implementation.
Code: `tools/fitness/tenancy/` (checks T1–T4, the CLI) and `tools/fitness/tenancy/static/` (T5).

```
make fitness-tenancy                 # = go run ./tools/fitness/tenancy
go run ./tools/fitness/tenancy -pg 18 -checks T1,T2   # one version, some checks
go test ./tools/fitness/tenancy/...  # a failing fixture per rule
```

It needs **Docker**: T1–T4 start throw-away PostgreSQL 16 and 18 containers (about 15 s for both).
There is no silent skip: with no daemon the job exits 2; the tests skip locally but fail when `CI` is set.
Images are pinned by digest in `pgenv.go`; `FITNESS_TENANCY_IMAGE_16` / `_18` override one (a mirror, an
air-gapped runner). A violation names the table (or file:line) and the rule: `T2 public.items [rls-force]: …`.

## The checks

| Check | What fails the build | Rule names |
| --- | --- | --- |
| T1 | Migration 1 does not create `public.tenants` with uuid `id` and `parent_tenant_id`; an object has a lower OID than `tenants`; files are not `NNNN_<owner>_<what>.sql`; the sequence does not start at 0001; a migration does not apply | `migration-1`, `tenants-first`, `tenants-columns`, `migration-name`, `migrations-apply` |
| T2 | A tenant table (partitions included) lacks `tenant_id uuid NOT NULL` with an FK to `tenants`; RLS not ENABLE and FORCE; policy not exactly `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid` for USING and WITH CHECK (no coalesce, no OR, no `true`, no extra permissive policy); `tenant_id` not first in the PK, every unique index (`pg_index.indisunique`: partial and expression indexes too) and every exclusion constraint; an FK into a tenant table that does not pair `tenant_id`; a view without `security_invoker`; a materialized view over a tenant table; a SECURITY DEFINER function not in the registry; registry entries that are reasonless, ownerless or stale; a registered-global table with an FK to a tenant table | `tenant-id`, `tenant-fk`, `rls-enable`, `rls-force`, `policy-shape`, `policy-missing`, `key-leading-tenant-id`, `fk-pairs-tenant-id`, `view-security-invoker`, `matview-over-tenant-table`, `security-definer`, `global-references-tenant`, `registry`, `registry-stale` |
| T3 | The runtime role is a superuser, has BYPASSRLS or owns an object (the product database itself included: a database owner can CREATE SCHEMA and `ALTER DATABASE SET search_path` for every session); it has TRUNCATE on a tenant table, CREATE on a product schema, CREATE on the product database or TEMPORARY on the database, directly, through `PUBLIC` or through any role it is a member of, with or without INHERIT (`SET ROLE` escapes it); it is a member (same rule) of a superuser, a BYPASSRLS role, the owner role, a role that owns objects or the database, or `pg_execute_server_program` / `pg_read_server_files` / `pg_write_server_files`; the owner (migration) role is a superuser or has BYPASSRLS | `role-superuser`, `role-bypassrls`, `role-membership`, `runtime-owns-object`, `runtime-truncate`, `runtime-create-schema`, `runtime-create-database`, `runtime-temporary` |
| T4 | Generated probes with tenants A and B and rows identical except `tenant_id`: cross-tenant read, insert, update and delete as the runtime role; no-context read and write on a fresh connection; B's value blocks A (a global unique key); a cross-tenant foreign key; `app.tenant_id` still set on the same connection after commit or rollback (SQL-14); the data-access package carries a passing `TestPoolRefusesSimpleProtocol` once it has Go files (SQL-20) | `read-cross-tenant`, `write-cross-tenant`, `write-no-context`, `unique-global`, `fk-cross-tenant`, `session-leak`, `sql-20`, `probe-seed`, `probe-error` |
| T5 | pgx imported outside `internal/platform/store`; River outside `internal/platform/jobs`; `set_config`/`SET` text outside `store`; SQL naming a registered-global table outside its owning package (Go strings and `.sql` query files), or in the report compiler's identifier registry; a `tenant.ID` minted (literal, conversion, a function returning one, index, slice) outside `tenant`, `authn`, `jobs`, registered functions and tests; `WithPlatform` called from an unregistered function; a type with `Kind() string` and no `tenant.ID` field that is not a registered platform job; `tenant.ID` with an Unmarshal/Scan/Set method; a tenant-scope OpenAPI operation with a `tenant_id` or `X-Tenant-*` parameter or body field | `pgx-boundary`, `river-boundary`, `set-config-text`, `global-table-sql`, `tenant-id-minting`, `with-platform-site`, `job-carries-tenant`, `tenant-id-decoder`, `openapi-tenant-param`, `registry-stale` |

Checks that depend on something absent activate when it appears: T1 with the first migration, the SQL-20
test with the first Go file in `store`, the OpenAPI rule with `api/openapi/`. On an empty tree the job
passes. Known limit: T4's foreign-key probe cannot run on a parent whose key is global (the seed already
fails with `unique-global`, which is the finding); it runs on every correctly paired parent.

## Bootstrap contract (what T-0037's installer must reproduce)

The job provisions its databases exactly as production must, so a migration written under the job runs
unchanged there:

- Two roles, both `LOGIN NOSUPERUSER NOBYPASSRLS`: **`activediq_owner`** (runs migrations, owns every
  object) and **`activediq_app`** (the runtime role; owns nothing).
- The owner owns the database and schema `public`; `PUBLIC` has no rights on the schema; the runtime role
  has `USAGE` on it.
- The runtime role does not own the database and holds no `CREATE` on it, directly, through `PUBLIC` or
  through any role it is a member of (the PostgreSQL default; the bootstrap must not widen it).
- No `TEMPORARY`: `PUBLIC` has no `TEMPORARY` on the product database (migration 0001 revokes it with
  `format('%I', current_database())`; an installer runs `REVOKE TEMPORARY ON DATABASE … FROM PUBLIC`), the
  runtime role is granted none, and T3 checks it through every role the runtime role is a member of.
  `pg_temp` is searched first, so a temp table planted by one tenant's transaction would capture another
  tenant's unqualified writes on a reused pooled connection (the same class as SQL-14).
- `ALTER DEFAULT PRIVILEGES FOR ROLE activediq_owner IN SCHEMA public` grants the runtime role
  `SELECT, INSERT, UPDATE, DELETE` on tables (never `TRUNCATE`) and `USAGE, SELECT` on sequences.
- Any other schema, and any non-default grant (a function, `EXECUTE`), is explicit SQL in a migration.
- `tenants` lives in `public`. Migration 0001 itself re-states the default privileges and the schema
  grant, so an installer that created only the two roles and a database the owner owns is enough: the
  script fails loudly if the split is missing or broken (roles absent, either one a superuser or
  `BYPASSRLS`, the runtime role a *member* of the owner, a superuser, a `BYPASSRLS` role or one of
  `pg_execute_server_program`, `pg_read_server_files`, `pg_write_server_files` (each "could be used to gain
  superuser-level access", https://www.postgresql.org/docs/16/predefined-roles.html), with or without
  `INHERIT`, since `SET ROLE` escapes RLS either way; the runtime role or a role it is a member of owning the
  database, a schema or any object, or able to `CREATE` in a schema, or holding `TEMPORARY` on the database). `store.Open` repeats the same refusal
  at startup (`roleRisk`), walking the memberships of the *login* (`session_user`), and also refuses a session
  that logged in as one role and runs as another (a `-c role=` startup option or `ALTER ROLE ... SET role`),
  because the login can `SET ROLE` back. Roles are cluster-level and the owner has no
  `CREATEROLE`, so the installer creates them; no migration does.
- The migration bookkeeping table is **not** created by any migration, so the job never sees it, and the
  registry does not list it (a registry entry for a table the job's database lacks fails `registry-stale`).
  The migrator (a follow-up ticket) creates and registers it. T-0037 ships no migrator.

## Migration naming

`migrations/NNNN_<owner>_<what>.sql`, four digits, one forward-only sequence starting at `0001`, lower
case. The `<owner>` segment is the **owner key**: the directory name of the owning top-level package
under an owner root ([ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md) rule 6), so
`0001_tenant_tenants.sql` is owned by `internal/platform/tenant`. It creates `tenants` and nothing
precedes it. Files are applied in order as the owner role, each as a multi-statement simple-protocol
execution.

## Exemption registry

`internal/platform/store/exempt/registry.json` (path overridable with `-registry`). JSON, strict (an
unknown key is an error). A missing file is an empty registry. Every entry has a `reason`.

```json
{
  "globalTables":    [{"table": "public.tenants", "reason": "…", "owner": "internal/platform/tenant"}],
  "securityDefiner": [{"function": "public.f(uuid)", "reason": "…"}],
  "platformPaths":   [{"package": "internal/modules/enroll", "function": "Service.Enroll", "reason": "…",
                       "withPlatform": true, "mintsTenantID": false}],
  "platformJobs":    [{"type": "internal/modules/sweep.Sweep", "reason": "…"}],
  "probeValues":     [{"column": "public.t.c", "value": "…", "reason": "…"}]
}
```

A global table names the one package whose SQL may reference it. An entry that names something that does
not exist (table, function, package, type) or that no longer needs the exemption fails as `registry-stale`;
an entry without a reason or owner fails as `registry`. `probeValues` gives T4 a bound text value for a
column whose CHECK or domain the generated value cannot satisfy.

## Contract with T-0037 (tenancy foundation): built

| Contract | Where |
| --- | --- |
| `tenant.ID`: unexported 16-byte value, `New()` and `Parse()` (canonical UUID text only, nil UUID rejected), `String`, `MarshalText`; no Unmarshal/Scan/Set method; no default-tenant constant | `internal/platform/tenant` |
| `store.DB` with `WithTenant(ctx, tenant.ID, fn)` and `WithPlatform(ctx, reason, fn)` (methods on the handle, so there is no package-level pool). Both open one transaction whose first statement is `set_config('app.tenant_id', $1, true), set_config('statement_timeout', $2, true)`; `WithPlatform` sets the tenant to empty. The pool is unexported; `fn` gets a `store.Tx` (the sqlc `DBTX` shape: `Exec`, `Query`, `QueryRow`) that cannot commit or reach the connection | `internal/platform/store` |
| `store.Open` refuses `default_query_exec_mode=simple_protocol` (`TestPoolRefusesSimpleProtocol`, SQL-20), a DSN that presets `app.tenant_id`, and a role that is a superuser, has `BYPASSRLS` or owns objects, and a login that runs as another role | `internal/platform/store` |
| The exemption registry, embedded (`exempt.JSON`) from the one file the job reads. Seeded with what exists today: `public.tenants` (owner `internal/platform/tenant`) and the bootstrap site. The ADR's other starting entries (migration bookkeeping, River, platform settings, hostname bindings, release metadata) are added by the ticket that creates each table, because an entry for a missing object is `registry-stale` | `internal/platform/store/exempt/registry.json` |
| First-run bootstrap `provision.FirstRun(ctx, db, name, initialisers...)`: under `WithPlatform` and an advisory lock it creates one tenant with `tenant.New()` if none exists; more than one is `ErrNotSingleTenant`. The row commits first; then the idempotent initialisers (`audit.InitTenant` is one, ADR-0005 rule 11) run in the tenant's own `WithTenant` transaction, on every call, so a tenant left half-initialised is completed | `internal/platform/tenant/provision` |
| Migration 0001, `0001_tenant_tenants.sql`: the role-split guard, default privileges, `tenants`; nothing else | `migrations/` (embedded by `migrations.FS`) |
| Test support: PostgreSQL 16 and 18 containers with the two roles (`storetest`, pins match `tools/fitness/tenancy/pgenv.go`: bump both); tenant seeding without naming the table (`tenanttest`) | `internal/platform/store/storetest`, `internal/platform/tenant/tenanttest` |

Still to come from other tickets: job argument types expose `Kind() string` and the job wrapper (T-0084);
platform-scope OpenAPI operations carry `x-activediq-scope: platform` (API tickets).
