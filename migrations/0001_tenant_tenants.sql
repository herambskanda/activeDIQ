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

DO $guard$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'activediq_app') THEN
    RAISE EXCEPTION 'role activediq_app does not exist: the installer must create the runtime role before migrating';
  END IF;
  IF current_user = 'activediq_app' THEN
    RAISE EXCEPTION 'migrations must run as the owner role, not as activediq_app';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN (current_user, 'activediq_app') AND (rolsuper OR rolbypassrls)) THEN
    RAISE EXCEPTION 'the migration role and activediq_app must be neither SUPERUSER nor BYPASSRLS (ADR-0002 rule 4)';
  END IF;
  IF pg_has_role('activediq_app', current_user, 'USAGE') THEN
    RAISE EXCEPTION 'activediq_app must not inherit the migration role';
  END IF;
END
$guard$;

-- The runtime role may use the schema but never create in it. The owner (this role) creates the objects.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO activediq_app;

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
