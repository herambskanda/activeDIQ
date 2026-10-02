-- 0001_tenant_tenants: the tenancy foundation (ADR-0002 rule 4). Owner: internal/platform/tenant.
--
-- This is the first migration. It creates `tenants` and nothing else, and it pins the two-role split
-- that every later migration and every query relies on:
--
--   activediq_owner  runs migrations (this script) and owns every object. Not a superuser, no BYPASSRLS.
--   activediq_app    the runtime role. Owns nothing, no BYPASSRLS, no TRUNCATE, no CREATE.
--
-- Both roles are created by the installer before the first run (a cluster-level act the owner cannot
-- do: it has no CREATEROLE). The script fails here, loudly, if the split is not in place, rather than
-- creating tables the runtime role could not use or that it could bypass.
--
-- `tenants` is a registered global table: it has no tenant_id and no RLS, because it is what a tenant
-- context is chosen from. Only the owning package, internal/platform/tenant, may name it in SQL.

-- The guard looks at every role activediq_app is a MEMBER of (itself included, direct or indirect,
-- whatever the INHERIT/SET options: a member that does not inherit can still SET ROLE to it) and
-- refuses when any of them is a superuser, has BYPASSRLS, is the migration role, owns the database or
-- any object, owns a schema, or can CREATE in one. internal/platform/store.roleRisk repeats this for
-- the runtime role at startup; keep the two in step.
DO $guard$
DECLARE
  r record;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'activediq_app') THEN
    RAISE EXCEPTION 'role activediq_app does not exist: the installer must create the runtime role before migrating';
  END IF;
  IF current_user = 'activediq_app' THEN
    RAISE EXCEPTION 'migrations must run as the owner role, not as activediq_app';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolbypassrls)) THEN
    RAISE EXCEPTION 'the migration role must be neither SUPERUSER nor BYPASSRLS (ADR-0002 rule 4)';
  END IF;
  FOR r IN
    SELECT x.rolname, CASE
        WHEN x.rolname = current_user THEN 'the migration role: activediq_app must not be a member of it'
        WHEN x.rolsuper THEN 'a superuser'
        WHEN x.rolbypassrls THEN 'a BYPASSRLS role'
        WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = current_database() AND datdba = x.oid) THEN 'the owner of the database'
        WHEN EXISTS (SELECT 1 FROM pg_shdepend d WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = x.oid AND d.deptype = 'o'
          AND d.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))) THEN 'an owner of objects'
        WHEN EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspowner = x.oid AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%') THEN 'the owner of a schema'
      END AS risk
    FROM pg_roles x
    WHERE pg_has_role('activediq_app', x.oid, 'MEMBER')
  LOOP
    IF r.risk IS NOT NULL THEN
      RAISE EXCEPTION 'activediq_app is a member of role % (%): the runtime role must not be, or be a member of, such a role (ADR-0002 rule 4)', r.rolname, r.risk;
    END IF;
  END LOOP;
END
$guard$;

-- The runtime role may use the schema but never create in it. The owner (this role) creates the objects.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO activediq_app;

-- With PUBLIC revoked, no role activediq_app is a member of may still create in a schema (a direct
-- grant, or the pre-15 default). Objects planted there could shadow ours.
DO $guard$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT x.rolname, n.nspname
    FROM pg_roles x, pg_namespace n
    WHERE pg_has_role('activediq_app', x.oid, 'MEMBER')
      AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
      AND has_schema_privilege(x.oid, n.oid, 'CREATE')
  LOOP
    RAISE EXCEPTION 'activediq_app (through role %) can CREATE in schema %: the runtime role must not create objects (ADR-0002 rule 4)', r.rolname, r.nspname;
  END LOOP;
END
$guard$;

-- Everything the owner creates in public from now on is usable by the runtime role for DML. TRUNCATE
-- is never granted (it ignores row-level security); sequences get USAGE and SELECT only.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO activediq_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO activediq_app;

CREATE TABLE public.tenants (
  id uuid PRIMARY KEY,
  parent_tenant_id uuid REFERENCES public.tenants (id),
  name text NOT NULL CHECK (name <> '' AND length(name) <= 200),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'deleting')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (parent_tenant_id IS DISTINCT FROM id)
);

COMMENT ON TABLE public.tenants IS 'Registered global table (ADR-0002): the list of tenants. No tenant_id, no RLS; only internal/platform/tenant references it in SQL.';
COMMENT ON COLUMN public.tenants.parent_tenant_id IS 'MSP hierarchy. RLS is always single-tenant; no policy admits descendants (ADR-0002, Hierarchy).';
