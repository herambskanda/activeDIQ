-- 0043_authz_tenant_owner_reconfirm: the built-in tenant-owner role may hold exactly the permissions
-- this guard names, and the first is connections.correlation.reconfirm (T-0453; follow-up of T-0282,
-- TM-D17 rule 4 (g)). Owner: internal/platform/rbac.
--
-- Migration 0034 made the role permission-free: every insert into authz_role_permissions for it was
-- refused. The role stays read-only apart from this named allow-list, so a permission reaches the
-- owner role only through a reviewed migration that edits the list below and
-- rbac.BuiltInRoles together (a test pins the two equal). Existing tenants receive the row the next
-- time rbac.SeedBuiltIns runs for them (idempotent); a migration cannot write it across tenants
-- because the table's row-level security is forced.

CREATE OR REPLACE FUNCTION public.authz_tenant_owner_role_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF TG_TABLE_NAME = 'authz_roles' THEN
    IF TG_OP = 'INSERT' THEN
      IF NEW.role_name = 'tenant-owner' AND NOT NEW.built_in THEN
        RAISE EXCEPTION 'authz: the name tenant-owner is reserved for the built-in role' USING ERRCODE = 'AD403';
      END IF;
    ELSIF OLD.role_name = 'tenant-owner' AND OLD.built_in
       AND (NEW.role_name IS DISTINCT FROM OLD.role_name OR NEW.built_in IS DISTINCT FROM OLD.built_in
            OR NEW.tier IS DISTINCT FROM OLD.tier OR NEW.id IS DISTINCT FROM OLD.id) THEN
      RAISE EXCEPTION 'authz: the built-in tenant-owner role is read-only' USING ERRCODE = 'AD403';
    ELSIF NEW.role_name = 'tenant-owner' AND NOT (OLD.role_name = 'tenant-owner') THEN
      RAISE EXCEPTION 'authz: the name tenant-owner is reserved for the built-in role' USING ERRCODE = 'AD403';
    END IF;
  ELSIF TG_TABLE_NAME = 'authz_role_permissions' THEN
    IF NEW.permission <> ALL (ARRAY['connections.correlation.reconfirm'])
       AND EXISTS (SELECT 1 FROM public.authz_roles r
                   WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.role_id AND r.role_name = 'tenant-owner' AND r.built_in) THEN
      RAISE EXCEPTION 'authz: the built-in tenant-owner role is read-only' USING ERRCODE = 'AD403';
    END IF;
  ELSE -- authz_assignments
    IF EXISTS (SELECT 1 FROM public.authz_roles r
               WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.role_id AND r.role_name = 'tenant-owner' AND r.built_in)
       AND (NEW.valid_until IS NOT NULL OR NEW.valid_from > now()) THEN
      RAISE EXCEPTION 'authz: a tenant-owner assignment cannot expire or start later' USING ERRCODE = 'AD403';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;
